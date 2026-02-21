# smrk-guegap-probe — v3 (ICP v2 + Kaspa Time Anchor)

This repo is a **GitHub-ready** workspace that implements:

- **v2 ICP-only screening** (N=256 stub) with:
  - on-chain **Registry** (job log + canonical input hash run_id)
  - on-chain **Compute** (runs screening and commits output + commit_hash)
  - output JSON includes **meta.compute** + **meta.registry** (audit context)
- **v3 Kaspa time-anchor (variant 2)**:
  - on-chain **Anchor canister** derives a **tECDSA secp256k1** key and signs the **anchor commitment**
  - it performs a **canister HTTP outcall** to an external **Kaspa broadcast proxy** (you run it)
  - the Registry stores anchor state per `run_id`

> The Kaspa broadcast is intentionally split:
> - **Signing / audit decisions happen on-chain** (ICP)
> - A thin **proxy** converts the signed payload to a real Kaspa transaction and broadcasts it.
>
> This keeps the “audit layer” fully on-chain while avoiding re-implementing the full Kaspa tx builder inside a canister.

---

## Repo layout

```
.
├── candid/
│   ├── registry.did
│   ├── compute.did
│   └── anchor.did
├── src/
│   ├── registry_canister/
│   ├── compute_canister/
│   └── anchor_canister/
└── tools/
    └── kaspa_proxy/   (optional helper: you run it off-chain)
```

---

## Requirements

- `dfx` (IC SDK)
- Rust toolchain
- wasm target:

```bash
rustup target add wasm32-unknown-unknown
```

Optional (recommended): `ic-wasm` for shrink/opt:

```bash
cargo install ic-wasm
```

If you **don’t** want to install `ic-wasm`, open `dfx.json` and remove:

```json
"packtool": "ic-wasm",
"args": "optimize"
```

---

## Local deploy (dfx)

```bash
dfx start --background
DFX_WARNING=-1 dfx deploy
```

After deploy you must set access-control principals in the Registry:

```bash
REGISTRY=$(dfx canister id registry_canister)
COMPUTE=$(dfx canister id compute_canister)
ANCHOR=$(dfx canister id anchor_canister)

dfx canister call registry_canister set_compute_canister "(principal \"$COMPUTE\")"
dfx canister call registry_canister set_anchor_canister  "(principal \"$ANCHOR\")"
```

---

## v2 flow: submit → compute → verify

### 1) Submit a canonical input blob

For testing, use `{}`:

```bash
dfx canister call registry_canister submit_job '(record { input = blob "\7b\7d" })'
```

It returns `run_id` (hex SHA-256 of the input).

### 2) Run screening (compute)

```bash
dfx canister call compute_canister run_screening '(record { run_id = "<RUN_ID_HEX>" })'
```

### 3) Read job

```bash
dfx canister call registry_canister get_job '(record { run_id = "<RUN_ID_HEX>" })'
```

You will get `output` (blob) which is UTF-8 JSON containing:

- `meta.run_id`
- `meta.input_sha256_hex`
- `meta.compute` (git_commit, crate_version, canister_version, build_ts)
- `meta.registry` (same for registry)

### 4) Verify commit hash

The registry stores `commit_hash_hex = SHA256(canonical_output_json)`.

---

## v3 flow: request anchor → anchor_run

### 1) Configure your Kaspa proxy endpoint

```bash
dfx canister call anchor_canister set_kaspa_endpoint '(record { base_url = "https://YOUR-PROXY"; api_key = null })'
```

### 2) Request anchoring (creates an anchor commitment)

```bash
dfx canister call registry_canister request_anchor '(record { run_id = "<RUN_ID_HEX>"; kaspa_network = "testnet" })'
```

### 3) Run anchor (signs + HTTP outcall)

```bash
dfx canister call anchor_canister anchor_run '(record { run_id = "<RUN_ID_HEX>"; kaspa_network = "testnet" })'
```

Registry anchor state:

```bash
dfx canister call registry_canister get_anchor '(record { run_id = "<RUN_ID_HEX>" })'
```

---

## Notes / next steps

- Compute canister uses a **deterministic stub** right now. Replace `screening_stub()` with a real N=256 kernel.
- Anchor canister currently signs the **anchor commitment** (32 bytes) via **threshold ECDSA**.
  On the IC, `sign_with_ecdsa` is the standard way to obtain secp256k1 signatures. See IC docs.
- A production-grade Kaspa anchor would build a real transaction whose payload embeds the commitment, then broadcast it.
  Kaspa nodes support transaction submission (e.g., `SubmitTransaction` in RPC).

---

## License

Apache-2.0
