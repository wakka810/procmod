#![allow(clippy::too_many_arguments)]

#[cfg(not(windows))]
fn main() {
    eprintln!("This program runs only on Windows.");
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows_app::run()
}

#[cfg(windows)]
mod windows_app {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::iter;
    use std::mem::size_of;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use anyhow::{Context, Result, anyhow, bail};
    use chrono::Local;
    use clap::{Parser, Subcommand};
    use windows::Win32::Foundation::{
        CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_ACCESS_DENIED,
        ERROR_INSUFFICIENT_BUFFER, ERROR_PARTIAL_COPY, ERROR_SEM_TIMEOUT, GetLastError, HANDLE,
        HMODULE, NTSTATUS,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFinalPathNameByHandleW,
        VOLUME_NAME_DOS,
    };
    use windows::Win32::System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess,
        DebugActiveProcessStop, DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT,
        EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, ReadProcessMemory, UNLOAD_DLL_DEBUG_EVENT,
        WaitForDebugEventEx,
    };
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, DEBUG_ONLY_THIS_PROCESS, OpenProcess, PROCESS_INFORMATION,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, STARTUPINFOW,
    };
    use windows::core::{HRESULT, PCWSTR, PWSTR};

    const WAIT_TIMEOUT_MS: u32 = 1_000;

    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about = "Inspect and monitor modules loaded in a Windows process",
        arg_required_else_help = true
    )]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand, Debug)]
    enum Command {
        /// Launch a new process in debug mode and monitor its modules
        Launch {
            /// Path to the executable to launch
            exe: PathBuf,
            /// Arguments to pass to the executable (use -- to separate)
            #[arg(trailing_var_arg = true)]
            args: Vec<String>,
        },
        /// Attach to an existing process by PID and monitor its modules
        Attach {
            /// Target process identifier
            pid: u32,
        },
    }

    struct ModuleInfoRecord {
        name: String,
    }

    pub fn run() -> Result<()> {
        let cli = Cli::parse();

        match cli.command {
            Command::Launch { exe, args } => launch_and_monitor(&exe, &args),
            Command::Attach { pid } => attach_and_monitor(pid),
        }
    }

    fn launch_and_monitor(exe: &Path, args: &[String]) -> Result<()> {
        if !exe.exists() {
            bail!("Executable not found: {}", exe.display());
        }

        let command_line = build_command_line(exe, args)?;
        let mut command_wide: Vec<u16> = command_line.encode_utf16().chain(iter::once(0)).collect();

        let mut startup = STARTUPINFOW::default();
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        let mut process_info = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                PWSTR(command_wide.as_mut_ptr()),
                None,
                None,
                false,
                DEBUG_ONLY_THIS_PROCESS,
                None,
                PCWSTR::null(),
                &mut startup,
                &mut process_info,
            )
            .ok()
            .with_context(|| format!("Failed to launch {}", exe.display()))?;
        }

        // We don't need the primary thread handle after startup
        unsafe { CloseHandle(process_info.hThread) }.ok();

        let session = DebugSession::new(process_info.dwProcessId, process_info.hProcess);
        session.monitor()
    }

    fn attach_and_monitor(pid: u32) -> Result<()> {
        unsafe { DebugActiveProcess(pid) }
            .ok()
            .with_context(|| format!("Failed to attach to PID {pid}"))?;

        let process_handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                .ok()
                .with_context(|| format!("Failed to open process {pid}"))?;

        let session = DebugSession::new(pid, process_handle);
        match session.monitor() {
            Ok(res) => Ok(res),
            Err(err) => {
                unsafe { DebugActiveProcessStop(pid) }.ok();
                Err(err)
            }
        }
    }

    struct DebugSession {
        pid: u32,
        process_handle: HANDLE,
        should_detach: Arc<AtomicBool>,
    }

    impl DebugSession {
        fn new(pid: u32, process_handle: HANDLE) -> Self {
            Self {
                pid,
                process_handle,
                should_detach: Arc::new(AtomicBool::new(false)),
            }
        }

        fn monitor(self) -> Result<()> {
            unsafe { DebugSetProcessKillOnExit(false) }.ok();

            let mut modules = self.print_initial_modules()?;

            let ctrl_c_flag = self.should_detach.clone();
            ctrlc::set_handler(move || {
                ctrl_c_flag.store(true, Ordering::SeqCst);
            })
            .context("Failed to install Ctrl+C handler")?;

            println!("Waiting for module load/unload events (press Ctrl+C to detach)...");

            let mut debug_event = DEBUG_EVENT::default();
            let mut exit_code: Option<u32> = None;

            loop {
                if self.should_detach.load(Ordering::SeqCst) {
                    println!("Detach requested, stopping debug session...");
                    unsafe { DebugActiveProcessStop(self.pid) }.ok();
                    break;
                }

                match unsafe { WaitForDebugEventEx(&mut debug_event, WAIT_TIMEOUT_MS) } {
                    Ok(()) => {}
                    Err(err) => {
                        if err.code() == HRESULT::from_win32(ERROR_SEM_TIMEOUT.0) {
                            continue;
                        }
                        unsafe { DebugActiveProcessStop(self.pid) }.ok();
                        bail!("WaitForDebugEventEx failed: {err:?}");
                    }
                }

                let continue_status = match debug_event.dwDebugEventCode {
                    code if code == CREATE_PROCESS_DEBUG_EVENT => {
                        self.handle_create_process(&debug_event, &mut modules)?;
                        DBG_CONTINUE
                    }
                    code if code == LOAD_DLL_DEBUG_EVENT => {
                        self.handle_load_dll(&debug_event, &mut modules)?;
                        DBG_CONTINUE
                    }
                    code if code == UNLOAD_DLL_DEBUG_EVENT => {
                        self.handle_unload_dll(&debug_event, &mut modules)?;
                        DBG_CONTINUE
                    }
                    code if code == EXIT_PROCESS_DEBUG_EVENT => {
                        exit_code = Some(unsafe { debug_event.u.ExitProcess.dwExitCode });
                        DBG_CONTINUE
                    }
                    code if code == EXCEPTION_DEBUG_EVENT => {
                        if let Some(status) = self.handle_exception(&debug_event)? {
                            status
                        } else {
                            DBG_EXCEPTION_NOT_HANDLED
                        }
                    }
                    _ => DBG_CONTINUE,
                };

                unsafe {
                    ContinueDebugEvent(
                        debug_event.dwProcessId,
                        debug_event.dwThreadId,
                        continue_status,
                    )
                }
                .ok()
                .context("ContinueDebugEvent failed")?;

                if debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                    let code = exit_code.unwrap_or_default();
                    println!(
                        "[{}] Process {} exited with code 0x{code:08X}",
                        timestamp_string(),
                        self.pid
                    );
                    break;
                }
            }

            Ok(())
        }

        fn print_initial_modules(&self) -> Result<HashMap<usize, ModuleInfoRecord>> {
            let modules = enumerate_modules(self.process_handle)?;
            println!("Initial modules ({}):", modules.len());
            for module in &modules {
                println!("  {}  {}", format_address(module.base), module.path);
            }

            Ok(modules
                .into_iter()
                .map(|m| (m.base, ModuleInfoRecord { name: m.path }))
                .collect())
        }

        fn handle_create_process(
            &self,
            event: &DEBUG_EVENT,
            modules: &mut HashMap<usize, ModuleInfoRecord>,
        ) -> Result<()> {
            unsafe {
                let info = event.u.CreateProcessInfo;
                if let Some(name) = resolve_image_name(
                    self.process_handle,
                    info.lpImageName,
                    info.fUnicode != 0,
                    info.hFile,
                )? {
                    let base = info.lpBaseOfImage as usize;
                    modules.insert(base, ModuleInfoRecord { name: name.clone() });
                    println!(
                        "[{}] CREATE {} (base {})",
                        timestamp_string(),
                        name,
                        format_address(base)
                    );
                }

                if !info.hFile.is_invalid() {
                    CloseHandle(info.hFile).ok();
                }
                CloseHandle(info.hThread).ok();
            }

            Ok(())
        }

        fn handle_load_dll(
            &self,
            event: &DEBUG_EVENT,
            modules: &mut HashMap<usize, ModuleInfoRecord>,
        ) -> Result<()> {
            unsafe {
                let info = event.u.LoadDll;
                let base = info.lpBaseOfDll as usize;
                let mut module_name = resolve_image_name(
                    self.process_handle,
                    info.lpImageName,
                    info.fUnicode != 0,
                    info.hFile,
                )?;
                if module_name.is_none() {
                    module_name =
                        get_module_path(self.process_handle, HMODULE(base as *mut c_void)).ok();
                }
                if !info.hFile.is_invalid() {
                    CloseHandle(info.hFile).ok();
                }
                let name =
                    module_name.unwrap_or_else(|| format!("<unknown @ {}>", format_address(base)));
                modules.insert(base, ModuleInfoRecord { name: name.clone() });
                println!(
                    "[{}] LOAD  {} (base {})",
                    timestamp_string(),
                    name,
                    format_address(base)
                );
            }
            Ok(())
        }

        fn handle_unload_dll(
            &self,
            event: &DEBUG_EVENT,
            modules: &mut HashMap<usize, ModuleInfoRecord>,
        ) -> Result<()> {
            unsafe {
                let info = event.u.UnloadDll;
                let base = info.lpBaseOfDll as usize;
                let entry = modules.remove(&base);
                let name = entry
                    .map(|m| m.name)
                    .unwrap_or_else(|| format!("<unknown @ {}>", format_address(base)));
                println!(
                    "[{}] UNLOAD {} (base {})",
                    timestamp_string(),
                    name,
                    format_address(base)
                );
            }
            Ok(())
        }

        fn handle_exception(&self, event: &DEBUG_EVENT) -> Result<Option<NTSTATUS>> {
            unsafe {
                let info = event.u.Exception;
                let code = info.ExceptionRecord.ExceptionCode;
                // Continue through initial breakpoints and single-step notifications
                const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
                const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
                const DBG_CONTROL_C: u32 = 0x40010005;
                let code_value = code.0 as u32;
                match code_value {
                    EXCEPTION_BREAKPOINT | EXCEPTION_SINGLE_STEP | DBG_CONTROL_C => {
                        Ok(Some(DBG_CONTINUE))
                    }
                    _ => {
                        println!(
                            "[{}] EXCEPTION 0x{code_value:08X} at {}",
                            timestamp_string(),
                            format_address(info.ExceptionRecord.ExceptionAddress as usize)
                        );
                        Ok(Some(DBG_EXCEPTION_NOT_HANDLED))
                    }
                }
            }
        }
    }

    impl Drop for DebugSession {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.process_handle) }.ok();
        }
    }

    struct EnumeratedModule {
        base: usize,
        path: String,
    }

    fn enumerate_modules(process: HANDLE) -> Result<Vec<EnumeratedModule>> {
        unsafe {
            const INITIAL_CAPACITY: usize = 64;
            const MAX_CAPACITY: usize = 4096;
            const MAX_ATTEMPTS: usize = 8;

            let tolerated = [
                HRESULT::from_win32(ERROR_PARTIAL_COPY.0),
                HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0),
                HRESULT::from_win32(ERROR_ACCESS_DENIED.0),
            ];

            let mut needed = 0u32;
            let mut capacity = INITIAL_CAPACITY;
            match EnumProcessModulesEx(process, ptr::null_mut(), 0, &mut needed, LIST_MODULES_ALL) {
                Ok(()) => {
                    if needed > 0 {
                        capacity = usize::min(
                            MAX_CAPACITY,
                            usize::max(needed as usize / size_of::<HMODULE>(), INITIAL_CAPACITY),
                        );
                    }
                }
                Err(err) => {
                    if !tolerated.contains(&err.code()) {
                        return Err(anyhow!(
                            "EnumProcessModulesEx (size query) failed: {:#?}",
                            err.code()
                        ));
                    }
                }
            }

            let mut modules = Vec::<HMODULE>::new();

            let mut attempt = 0;
            loop {
                if capacity == 0 || capacity > MAX_CAPACITY {
                    return Err(anyhow!(
                        "EnumProcessModulesEx required more than {MAX_CAPACITY} module handles"
                    ));
                }

                modules.resize(capacity, HMODULE::default());
                let mut needed_bytes = 0u32;
                match EnumProcessModulesEx(
                    process,
                    modules.as_mut_ptr(),
                    (modules.len() * size_of::<HMODULE>()) as u32,
                    &mut needed_bytes,
                    LIST_MODULES_ALL,
                ) {
                    Ok(()) => {
                        let count = if needed_bytes == 0 {
                            modules
                                .iter()
                                .take_while(|module| !module.is_invalid())
                                .count()
                        } else {
                            (needed_bytes as usize / size_of::<HMODULE>()).min(modules.len())
                        };
                        modules.truncate(count);
                        break;
                    }
                    Err(err) => {
                        if !tolerated.contains(&err.code()) {
                            return Err(anyhow!(
                                "EnumProcessModulesEx failed while reading modules: {:#?}",
                                err.code()
                            ));
                        }

                        attempt += 1;
                        if attempt >= MAX_ATTEMPTS {
                            modules.clear();
                            break;
                        }

                        if needed_bytes > 0 {
                            capacity = usize::min(
                                MAX_CAPACITY,
                                usize::max(
                                    needed_bytes as usize / size_of::<HMODULE>(),
                                    modules.len().saturating_mul(2),
                                ),
                            );
                        } else {
                            capacity = usize::min(MAX_CAPACITY, modules.len().saturating_mul(2));
                            if capacity == modules.len() {
                                capacity = usize::min(MAX_CAPACITY, capacity + INITIAL_CAPACITY);
                            }
                        }

                        continue;
                    }
                }
            }

            let mut results = Vec::with_capacity(modules.len());
            for module in modules {
                if module.is_invalid() {
                    continue;
                }
                let path = get_module_path(process, module)?;
                results.push(EnumeratedModule {
                    base: module.0 as usize,
                    path,
                });
            }

            results.sort_by_key(|m| m.base);
            Ok(results)
        }
    }

    fn get_module_path(process: HANDLE, module: HMODULE) -> Result<String> {
        let mut buffer = vec![0u16; 260];
        loop {
            let length = unsafe { GetModuleFileNameExW(process, module, &mut buffer) } as usize;

            if length == 0 {
                bail!("GetModuleFileNameExW failed (error {:?})", unsafe {
                    GetLastError()
                });
            }

            if length == buffer.len() {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }

            buffer.truncate(length);
            return String::from_utf16(&buffer).context("Failed to decode module path");
        }
    }

    fn resolve_image_name(
        process: HANDLE,
        pointer: *mut c_void,
        is_unicode: bool,
        file_handle: HANDLE,
    ) -> Result<Option<String>> {
        if !pointer.is_null() {
            if let Some(name) = read_pointer_string(process, pointer as usize, is_unicode)? {
                return Ok(Some(name));
            }
        }

        if !file_handle.is_invalid() && file_handle != HANDLE::default() {
            if let Some(name) = path_from_handle(file_handle) {
                return Ok(Some(name));
            }
        }

        Ok(None)
    }

    fn read_pointer_string(
        process: HANDLE,
        address: usize,
        is_unicode: bool,
    ) -> Result<Option<String>> {
        let mut ptr_buf = vec![0u8; size_of::<usize>()];
        let mut read = 0usize;
        if unsafe {
            ReadProcessMemory(
                process,
                address as *const c_void,
                ptr_buf.as_mut_ptr() as *mut c_void,
                ptr_buf.len(),
                Some(&mut read),
            )
        }
        .is_err()
            || read != ptr_buf.len()
        {
            return Ok(None);
        }
        let remote_addr = usize::from_ne_bytes(ptr_buf.try_into().unwrap());
        if remote_addr == 0 {
            return Ok(None);
        }
        if is_unicode {
            read_remote_utf16(process, remote_addr).map_err(Into::into)
        } else {
            read_remote_utf8(process, remote_addr).map_err(Into::into)
        }
    }

    fn read_remote_utf16(process: HANDLE, mut address: usize) -> Result<Option<String>> {
        const CHUNK: usize = 256;
        const MAX_CHARS: usize = 32_768;
        let mut collected = Vec::<u16>::new();
        loop {
            let mut buffer = vec![0u16; CHUNK];
            let mut bytes_read = 0usize;
            if unsafe {
                ReadProcessMemory(
                    process,
                    address as *const c_void,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() * size_of::<u16>(),
                    Some(&mut bytes_read),
                )
            }
            .is_err()
                || bytes_read == 0
            {
                break;
            }
            let chars_read = bytes_read / size_of::<u16>();
            for &code_unit in &buffer[..chars_read] {
                if code_unit == 0 {
                    return Ok(Some(
                        String::from_utf16(&collected)
                            .context("Invalid UTF-16 data in remote process")?,
                    ));
                }
                collected.push(code_unit);
                if collected.len() >= MAX_CHARS {
                    return Ok(Some(
                        String::from_utf16(&collected)
                            .context("Invalid UTF-16 data in remote process")?,
                    ));
                }
            }
            address += chars_read * size_of::<u16>();
        }
        Ok(None)
    }

    fn read_remote_utf8(process: HANDLE, mut address: usize) -> Result<Option<String>> {
        const CHUNK: usize = 256;
        const MAX_LEN: usize = 32_768;
        let mut collected = Vec::<u8>::new();
        loop {
            let mut buffer = vec![0u8; CHUNK];
            let mut bytes_read = 0usize;
            if unsafe {
                ReadProcessMemory(
                    process,
                    address as *const c_void,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(),
                    Some(&mut bytes_read),
                )
            }
            .is_err()
                || bytes_read == 0
            {
                break;
            }
            for &byte in &buffer[..bytes_read] {
                if byte == 0 {
                    return Ok(Some(
                        String::from_utf8(collected)
                            .context("Invalid UTF-8 data in remote process")?,
                    ));
                }
                collected.push(byte);
                if collected.len() >= MAX_LEN {
                    return Ok(Some(
                        String::from_utf8(collected)
                            .context("Invalid UTF-8 data in remote process")?,
                    ));
                }
            }
            address += bytes_read;
        }
        Ok(None)
    }

    fn path_from_handle(handle: HANDLE) -> Option<String> {
        unsafe {
            if handle.is_invalid() || handle == HANDLE::default() {
                return None;
            }
            let mut size = 512usize;
            loop {
                let mut buffer = vec![0u16; size];
                let flags =
                    GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0);
                let len = GetFinalPathNameByHandleW(handle, &mut buffer, flags);
                if len == 0 {
                    return None;
                }
                if (len as usize) >= buffer.len() {
                    size = len as usize + 1;
                    continue;
                }
                buffer.truncate(len as usize);
                let raw = String::from_utf16(&buffer).ok()?;
                return Some(normalize_device_path(raw));
            }
        }
    }

    fn normalize_device_path(raw: String) -> String {
        if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{}", rest)
        } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
            rest.to_string()
        } else {
            raw
        }
    }

    fn build_command_line(exe: &Path, args: &[String]) -> Result<String> {
        let exe_str = exe
            .to_str()
            .ok_or_else(|| anyhow!("Executable path contains invalid UTF-16 data"))?;
        let mut parts = Vec::with_capacity(args.len() + 1);
        parts.push(quote_argument(exe_str));
        for arg in args {
            parts.push(quote_argument(arg));
        }
        Ok(parts.join(" "))
    }

    fn quote_argument(arg: &str) -> String {
        if arg.is_empty() {
            return "\"\"".to_string();
        }
        let needs_quotes = arg
            .chars()
            .any(|c| c.is_ascii_whitespace() || matches!(c, '"'));
        if !needs_quotes {
            return arg.to_string();
        }
        let mut result = String::with_capacity(arg.len() + 2);
        result.push('"');
        let mut backslashes = 0;
        for ch in arg.chars() {
            match ch {
                '\\' => {
                    backslashes += 1;
                }
                '"' => {
                    result.push_str(&"\\".repeat(backslashes * 2 + 1));
                    result.push('"');
                    backslashes = 0;
                }
                _ => {
                    if backslashes > 0 {
                        result.push_str(&"\\".repeat(backslashes));
                        backslashes = 0;
                    }
                    result.push(ch);
                }
            }
        }
        if backslashes > 0 {
            result.push_str(&"\\".repeat(backslashes * 2));
        }
        result.push('"');
        result
    }

    fn timestamp_string() -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
    }

    fn format_address(addr: usize) -> String {
        if size_of::<usize>() == 8 {
            format!("0x{addr:016X}")
        } else {
            format!("0x{addr:08X}")
        }
    }
}
