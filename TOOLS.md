# Tooling notes

## If `ic-wasm` is missing

If `dfx deploy` fails with something like `packtool ic-wasm not found`, either:

```bash
cargo install ic-wasm
```

or remove the packtool section from `dfx.json`:

```json
"defaults": {
  "build": {
    "packtool": "ic-wasm",
    "args": "optimize"
  }
}
```

## Rust WASM target

```bash
rustup target add wasm32-unknown-unknown
```
