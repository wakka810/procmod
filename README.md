## Building
```bash
cargo build --release
```

## Usage
```bash
# Launch and monitor a new process
procmod launch C:\\Path\\To\\app.exe -- --arg1 value

# Attach to an existing process
procmod attach --pid 1234
```
