# Thunderducks sample bot

Uses **public node RPC only**. No device keys, no E2EE session access.

```bash
cargo build -p tducks
cargo run -p tducks -- serve --bind 127.0.0.1:8788
TD_RPC=http://127.0.0.1:8788 node src/honk-bot.js "hello"
npm test
```
