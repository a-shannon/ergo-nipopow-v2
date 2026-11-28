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

1. **Cold `V2Production128` Verification in a Web Worker:** Verifies all `1,827,840` Ergo mainnet headers (`5.99 MiB` `.gz`) under bounded EIP-0054 anti-DoS caps, enforces `ProfileId::V2Production128`, verifies the 128-bit ZisK STIR half (reporting `openvm_half_verified: false`; full Dual verification runs in `host-aggregator`), and saves a `5.6 KiB` `LightCheckpoint` to `localStorage`.
2. **Live Plain-Header Sync Against Any Public Ergo Node:** Fetches strictly contiguous modern headers from `/blocks/chainSlice` (default `https://node.ergo.watch`, CORS-enabled) using lossless 64-bit integer JSON parsing (`web/nipopow-v2.js`), enforces Ergo's +20 min future-timestamp drift guard, and verifies every parent link, EIP-37 retarget, and Autolykos v2 PoW inside WebAssembly with **zero STARK prover dependency**.
3. **Trustless Live Multi-Tx AVL+ `ADProofs` & Tx Merkle Verification (Up to 1,024 Blocks Behind Tip):** Fetches a certified modern block by its header-chain `blockId` (zero branch-mixing on reorgs), enforces `k_0 = 64` confirmation depth by default (with explicit opt-in for unconfirmed tip inspection), verifies `ADProofs` (`toLookup ++ toRemove ++ toAppend` with `Some(_)` lookup existence and duplicate external spend rejection), and binds `merkle_tx_proof.leafData == expected_tx_id` inside WASM (~`1.5–2 ms`), alongside the bundled `1,827,976` offline fixture and interactive baseline-verified 1-bit PoW tamper test.
