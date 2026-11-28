# `@ergo-nipopow-v2/light-wasm`

Zero-dependency strict 128-bit (`V2Production128`) Ergo NiPoPoW V2 WebAssembly light-client verifier for wallets (Nautilus, Minotaur, Fleet SDK dApps), browsers, and Node.js.

- **Zero runtime npm dependencies, zero prover SDK, zero JS WASM imports.**
- **Cold genesis-to-tip verification** (`1,827,840` mainnet headers in ~4.4 s in V8 from `5.99 MiB` gzip-compressed certificate + tail; verifies the 128-bit ZisK STIR half and explicitly reports `openvm_half_verified: false` for Dual containers).
- **Indefinite plain-header continuation** (`extendTail`, ~160 KiB/day, +20 min future-drift guard, zero STARK prover dependency).
- **Trustless live multi-tx AVL+ `ADProofs` & Scorex Tx Merkle verification** (`verifyCheckpointBlockState`, enforcing `k_0 = 64` confirmation depth by default, `expected_tx_id == leafData` binding, `Some(_)` lookup existence for external `dataInputs`, and intra-block spend cancellation matching `ErgoState.stateChanges`).
- **WASM binary:** Build `ergo_nipopow_v2_light.wasm` from source (below) or fetch the matching versioned binary from the repository's GitHub Pages / CI artifacts.

## Build the `.wasm` Binary

From the repository root:

```bash
rustup target add wasm32-unknown-unknown
cargo build -p ergo-nipopow-v2-light --no-default-features --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/ergo_nipopow_v2_light.wasm packages/light-wasm/
```

## Minimal Wallet / dApp Usage (Browser or Node.js >= 18)

```js
import {
  NiPoPoWV2Wasm,
  fetchLiveHeadersU32le,
  fetchLiveBlockProofBundle,
} from "@ergo-nipopow-v2/light-wasm";

// 1. Instantiate pure-Rust WASM verifier (~817 KiB gzip-9, zero imports)
const client = await NiPoPoWV2Wasm.load(wasmBytes);

// 2. Cold-verify 128-bit certificate + exact tail once; persist 5.6 KiB checkpoint
const cold = client.verifyCert(certGzBytes, tailGzBytes);
let checkpointJson = cold.checkpoint_json;

// 3. Catch up to live Ergo mainnet headers from any untrusted node (zero STARK)
const { u32le } = await fetchLiveHeadersU32le(
  "https://node.ergo.watch",
  cold.tip_height,
  cold.tip_height + 256
);
const synced = client.extendTail(checkpointJson, u32le);
checkpointJson = synced.checkpoint_json;

// 4. Trustlessly verify any certified block's real ADProofs + Tx Merkle proof
const bundle = await fetchLiveBlockProofBundle(
  "https://node.ergo.watch",
  synced.tip_height,
  synced.tip_height
);
const verified = client.verifyCheckpointBlockState(
  checkpointJson,
  bundle.headerChainDescU32le,
  bundle.blockProofJson
);
console.log(verified.height, verified.next_state_root, verified.tx_merkle_verified);
```

Live browser demo: https://a-shannon.github.io/ergo-nipopow-v2/
