# Kaspa broadcast proxy (optional)

The **anchor_canister** uses an IC **HTTP outcall** to:

`POST {base_url}/broadcast`

with JSON:

```json
{
  "network": "testnet",
  "run_id": "<sha256(input)>",
  "anchor_commitment_hex": "<32-byte hex>",
  "pubkey_hex": "<secp256k1 pubkey hex>",
  "signature_hex": "<tECDSA signature hex>"
}
```

This proxy is responsible for:

1) building a real Kaspa transaction that **embeds** `anchor_commitment_hex` in the payload
2) signing it (using `signature_hex` / `pubkey_hex` as part of your signing flow)
3) broadcasting via a Kaspa node (`SubmitTransaction` exists in Kaspa RPC).

Then respond with:

```json
{ "txid": "<kaspa_txid>" }
```

> The included `server.js` is a **stub** so the end-to-end IC side works immediately.
> Replace the TODO section with your preferred Kaspa tooling (Go kaspad, Rusty-Kaspa, Wallet SDK, etc.).
