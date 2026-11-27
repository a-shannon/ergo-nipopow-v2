# Zero-Backend Browser WebAssembly Light Client (`web/`)

**Live Demo:** https://a-shannon.github.io/ergo-nipopow-v2/ (automatically built from source and deployed via `.github/workflows/pages.yml` with the verified `v0.4.0` `.gz` release assets served same-origin).

Run Ergo NiPoPoW V2 (`V2Production128`) directly in any modern browser with **zero npm packages, zero bundler, zero backend server, and zero prover SDK**.

## Quickstart

```bash
# 1. Build the standalone wasm32-unknown-unknown binary (~817 KiB gzip-9, zero JS imports)
rustup target add wasm32-unknown-unknown
cargo build -p ergo-nipopow-v2-light --no-default-features --target wasm32-unknown-unknown --release

# 2. Place the compiled .wasm and v0.4.0 compressed release assets into web/assets/
mkdir -p web/assets
cp target/wasm32-unknown-unknown/release/ergo_nipopow_v2_light.wasm web/assets/
gh release download v0.4.0 -R a-shannon/ergo-nipopow-v2 -D web/assets \
  -p "ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin.gz" \
  -p "tail-1819645-1827840.u32le.gz"

# 3. Serve the repository root over HTTP (for Web Worker ES modules)
python3 -m http.server 8080
# Open http://localhost:8080/web/
```

## What It Demonstrates

1. **Cold 128-bit Verification in a Web Worker:** Verifies all `1,827,840` Ergo mainnet headers (`5.99 MiB` `.gz`), enforces `ProfileId::V2Production128`, and saves a `5.6 KiB` `LightCheckpoint` to `localStorage`.
2. **Live Plain-Header Sync Against Any Public Ergo Node:** Fetches live headers from `/blocks/chainSlice` (default `https://node.ergo.watch`, CORS-enabled), canonically encodes them in pure JavaScript (`web/nipopow-v2.js`), and verifies every parent link, EIP-37 retarget, and Autolykos v2 PoW inside WebAssembly with **zero STARK prover dependency**.
3. **Trustless Live Multi-Tx AVL+ `ADProofs` & Tx Merkle Verification (Any Certified Height):** Fetches any certified block `H <= tip_height` (plus its minimal descending header chain back from `checkpoint.tip_id`, full `ADProofs`, `dataInputs` lookups, intra-block spend cancellation, and `/blocks/{id}/proofFor/{txId}`) straight from any untrusted Ergo node and verifies the AVL+ state transition and Tx Merkle inclusion in ~`1.5–2 ms` inside WASM, alongside the bundled `1,827,976` offline fixture and interactive 1-bit PoW tamper test.
