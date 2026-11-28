# Ergo NiPoPoW V2

**128-Bit Analytical Sampling & Incremental Transparent STARK Certification of Ergo Header History**

A. Shannon · 28 November 2026 · MIT OR Apache-2.0

[![CI](https://github.com/a-shannon/ergo-nipopow-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/a-shannon/ergo-nipopow-v2/actions/workflows/ci.yml)
[![Live Browser WASM Demo](https://img.shields.io/badge/Live%20Demo-Browser%20WASM%20Light%20Client-ff5e18)](https://a-shannon.github.io/ergo-nipopow-v2/)

---

## Overview

**Ergo NiPoPoW V2** certifies Ergo's complete canonical header history from genesis (`1..=1,827,840`) using `V2Production128` (**128-bit analytical protocol sampling/race error `<= 2^-128.35 < 2^-128`** via exact rational certification, reported separately from ZisK STARK soundness `~2^-128` JBR, 256-bit hash collision assumptions [`128-bit` classical / `~2^85` generic quantum collision], and Ergo's common-prefix premise `ε_CP`) with **zero hard fork, zero soft fork, zero miner change, zero trusted setup, and zero elliptic-curve pairing assumptions**.

All **1,827,840 canonical Ergo mainnet headers** (tip `20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`, `407.07 MiB` raw headers) have been proved end-to-end into a **100% Path-Independent Reproducible Heterogeneous Dual-Proof `V2Certificate`** pairing two completely independent transparent hash-based zkVMs over the **exact byte-identical `BootstrapStatement`** (`SHA-256 = e7981fbc64af4abdd38292792584f1d9850ee6fb293f12c27f2dead07a55edbc`):

- **Proof A — ZisK `v1.4.0-alpha`** (`RV64IMA`, `Goldilocks^3`, 256-bit `BLAKE3`, DEEP-ALI + **STIR `--minimal`**): **`245.96 KiB` (`251,864 B`)**, verified on pure CPU in **`2 ms`**. Full 7-year genesis-to-STIR run completed in **`27 min 03 s`** on `2× RTX 5090`. All 3 recursive guest ROM roots (`leaf-segment`, `agg-l1`, `agg-root`) reproduce bit-for-bit from source via `scripts/verify_reproducible_vks.sh` and `docker/reproducible-zisk-vks.Dockerfile`.
- **Proof B — OpenVM `v2.1.0`** (`RV32IM`, `BabyBear^4`, `Poseidon2`, **SWIRL/WHIR**, zkSecurity audited & partially Lean-verified [RV32IM/memory/SHA-2 circuits], **100-bit proven RBR security** via OpenVM `v2.1.0` default `*_with_100_bits_security` parameters as independent defense-in-depth alongside 128-bit ZisK): **`533.5 KiB` (`546,289 B`)**. Full verification of BOTH halves runs in `host-aggregator verify-cert`; the lightweight `wasm32` verifier (`ergo-nipopow-v2-light`) verifies the ZisK STIR half only and explicitly reports `openvm_half_verified = false`.

### What's New in `v0.4.3` (Multi-Model Security & Consensus Hardening — Zero VK Changes)

Following three independent read-only audits across the cryptography, WASM/JS light client, red-team DoS surface, and EIP-0054 specification (zero critical bugs in the core proof machinery; `crates/ergo-nipopow-v2-core/src/` untouched so all `v0.4.0` reproducible VKs remain 100% identical):

- **Strict `V2Production128` Profile Admission on ALL Extension Paths:** Enforced fail-closed in `extend_light_checkpoint_bytes`, `extend_light_checkpoint_bytes_at_time`, `wasm_extend_tail`, `wasm_verify_live_state_proof`, and browser `localStorage` resume.
- **Confirmation Depth (`k_0 = 64`) & Ergo +20 min Clock Drift Guard:** `verify_checkpoint_block_state` enforces `>= 64` confirmations by default (returning `confirmations` & `confirmed_k0`; unconfirmed recent blocks require explicit opt-in), and `extend_light_checkpoint_bytes_at_time` rejects future header timestamps exceeding `now + 20 min`.
- **Strict Requested-`txId` Merkle Binding & `dataInputs` Existence:** `verify_checkpoint_block_state` now binds `merkle_tx_proof.leafData == expected_tx_id`, returns `verified_tx_id` directly from WASM, and rejects `Ok(None)` (proof of non-existence) on `Operation::Lookup` for claimed external `dataInputs`.
- **Enforced Anti-DoS Bounds & Pinned VKs:** Enforced EIP-0054 compressed/decompressed caps (`12/16/8 MiB`, `take(cap + 1)`), bounded `bincode` with `reject_trailing_bytes()`, `1..=514 B` per-header frames with checked arithmetic, `wasm_alloc` caps + `try/finally` cleanup, compile-time pinned `v0.4.0` ZisK & OpenVM VKs in `host-aggregator verify-cert` (`--unsafe-override-vk` required to override), and chain-commitment (`query_header_id`) equal-work tie-breaking in `compare_peer_certificates`.
- **Lossless 64-Bit Ergo `Long` JSON & Reorg-Safe Block Fetching (`web/`, `packages/light-wasm/`):** `parseJsonLosslessInts` preserves `> 2^53 - 1` box values/token amounts before `BigInt` conversion; `fetchLiveBlockProofBundle` fetches `/blocks/{certifiedBlockId}` directly from the header chain instead of `/blocks/at/{H}`; `fetchLiveHeadersU32le` enforces strict contiguous pagination and timeouts.
- **Honest Dual vs Light Reporting:** `ergo-nipopow-v2-light` and WASM now explicitly report `verified_proof: "ZiskStirV14_only (OpenVM half unverified in light verifier)"` and `openvm_half_verified: false` when inspecting a Dual container.

### Highlights from `v0.4.2` (Live Multi-Tx Any-Block `ADProofs`, GitHub Pages Live Demo & `@ergo-nipopow-v2/light-wasm` SDK)

- **Live Any-Block Multi-Tx `ADProofs` & Tx Merkle in Browser WASM ([Try Live Demo](https://a-shannon.github.io/ergo-nipopow-v2/)):** Added `verify_block_ad_proofs_with_lookups` and `verify_checkpoint_block_state` (`wasm_verify_checkpoint_block_state`), matching Ergo reference node `ErgoState.stateChanges` / `StateChanges.operations` (`toLookup ++ toRemove ++ toAppend`, supporting `dataInputs` lookups and intra-block spend cancellation). Verified live in V8 against `https://node.ergo.watch` on multi-tx mainnet blocks (`1,828,096` with 4 txs / 2 intra-block spends / `10.5 KiB` `ADProofs` in **`1.9 ms`**; `1,828,095` with `dataInputs` lookup / `38.7 KiB` `ADProofs` in **`1.4 ms`**).
- **Zero-Dependency TypeScript/ESM Wallet Package (`packages/light-wasm/`):** Ready-to-consume `@ergo-nipopow-v2/light-wasm` package (`package.json`, `index.js`, `index.d.ts`, `README.md`) with zero runtime npm dependencies and canonical `ErgoHeader` + `ErgoBox` binary encoders.
- **Official-Format Transport EIP Proposal (`docs/EIP-NIPOPOW-V2-TRANSPORT.md`):** CC0 read-only REST & P2P node transport specification (`Forking: not needed`) aligned with `ergoplatform/eips`.

### Highlights from `v0.4.1` (Issue #2 Hardening)

- **Strict `V2Production128` Profile Enforcement & Standalone OpenVM Guard (Issue #2):** Both `ergo-nipopow-v2-light` (native CLI, WASM, `compare-certs`) and `host-aggregator` (`verify-cert`, `assemble-zisk-cert`, `assemble-dual-cert`) now enforce `cert.statement.profile == ProfileId::V2Production128` fail-closed (preventing profile-downgrade certificates) and report `profile=V2Production128` explicitly. `host-aggregator verify-cert` also refuses standalone `OpenVmSwirlV21` by default unless `--allow-non-128-standalone-openvm` is explicitly passed, documenting OpenVM `v2.1.0`'s 100-bit proven RBR security level transparently.
- **Conservative Exact-Rational Reporting (`scripts/certify_profiles.py`):** Exponents are now conservatively truncated toward zero (never rounded toward stronger security), explicitly reporting `eps_early = (2^80 + 1)·(1/2 + 2^-37)^210 = 2^-130 · (1 + 3.06e-9) <= 2^-129.99` while confirming `union(5) <= 2^-128.35 < 2^-128` and conservative `union(6) <= 2^-128.13 < 2^-128`.
- **Zero-Backend Live Browser WASM Demo (`web/` — [Try Live on GitHub Pages](https://a-shannon.github.io/ergo-nipopow-v2/)):** Self-contained HTML + ES module (`web/index.html`, `web/nipopow-v2.js`, `web/worker.js`) executing `ergo_nipopow_v2_light.wasm` (`816.9 KiB` gzip-9, zero npm) in a browser Web Worker, with live plain-header `extend-tail` syncing directly against any public Ergo node REST API up to the current mainnet tip and trustless AVL+ `ADProofs` verification.
- **Ergo Node Transport EIP Draft (`docs/EIP-NIPOPOW-V2-TRANSPORT.md`):** Read-only REST and P2P specification for serving `(V2Certificate, exact_tail)` bundles and frozen L1 archives from Ergo nodes with zero consensus changes.

### Highlights from `v0.4.0` (100% Reproducible Dual-Proof Snapshot, Executable V8 WASM, Live Post-STARK `1,827,976` `ADProofs` & Untrusted Multi-Peer Fork Selection)

1. **100% Path-Independent Reproducible Mainnet Dual-Proof Snapshot (`--remap-path-prefix` on BOTH ZisK & OpenVM):**
   - Re-proved all `1,827,840` Ergo mainnet headers from genesis under deterministic `--remap-path-prefix` builds with all 6 guest `Cargo.lock` files committed (`guests-zisk/*` and `guests/*`) and **zero build-host paths** in all 6 compiled ELFs.
   - `scripts/verify_reproducible_vks.sh` (and the pinned `docker/reproducible-zisk-vks.Dockerfile`) rebuilds all 3 ZisK `v1.4.0-alpha` guests (`leaf-segment`, `agg-l1`, `agg-root`) and the OpenVM `v2.1.0` `leaf-segment` `.vmexe` from public sources and confirms **100% bit-for-bit parity** against the **live `v0.4.0` mainnet Dual-Proof snapshot** (`ALL_3_CANONICAL_PATH_INDEPENDENT_ZISK_VKS_REPRODUCED_BIT_FOR_BIT` + `OPENVM_PATH_INDEPENDENT_LEAF_VMEXE_REPRODUCED_BIT_FOR_BIT`).
2. **Executable `wasm32-unknown-unknown` Binary Executed Live Inside V8 (`crates/ergo-nipopow-v2-light/src/wasm.rs`, `wasm/verify_v8.mjs`):**
   - Standalone `cdylib` (`ergo_nipopow_v2_light.wasm`, **`< 1 MiB` gzip-9** with **zero JS imports, zero prover SDK, zero CUDA, zero C++**), executed live inside Node.js V8 on every CI run:
     - Cold 128-bit verification of all `1,827,840` blocks (`.gz` ZisK STIR + `.gz` exact tail): **`4.574 s`** (`inst = 28.5 ms`).
     - Returning-user `extend-tail` (`+136` live headers `1,827,841..=1,827,976`, zero STARK, crosses EIP-37 retarget): **`28.4 ms`**.
     - Live post-STARK block **`1,827,976`** `ADProofs` + Scorex Tx Merkle verification inside V8: **`27.6 ms`**.
     - Isolated 1-bit PoW tamper rejected fail-closed inside V8 (`Pow(Target)`).
3. **Live Post-STARK, Post-EIP-37-Retarget Block `1,827,976` `ADProofs` & Tx Merkle (`verify-live-state-proof`):**
   - Proves that returning light clients never need a STARK prover again even for UTXO state proofs on freshly mined blocks after a difficulty retarget: extends `ckpt-1827840.json` to live mainnet block `1,827,976` (`+136` plain headers, crossing EIP-37 retarget `105028762 -> 105229481` at `1,827,969`), then verifies the real **`2,828 B` `ADProofs`** AVL+ batch state transition (`59209366...1619 -> 25b40830...4819`, 1 spent input + 2 canonically serialized created boxes) and Scorex Tx Merkle inclusion proof in **`0.05 ms`** (`0.030 s` total including 136-header extension, `3/3` tamper checks rejected).
4. **Untrusted Multi-Peer Fork Selection (`compare-certs`, `compare_peer_certificates`):**
   - Evaluates competing `(V2Certificate, exact_tail)` pairs from multiple untrusted peers, rejects invalid/tampered peers fail-closed, and deterministically selects the heaviest valid chain (`select_best`). Verified in CI against a 1-bit tampered malicious peer plus honest Dual/STIR mirrors.
5. **Exact-Tail Tip Binding & Permissionless CPU-Only Renewal (`PR #1` merged, `scripts/renew_zisk_cpu.sh`):**
   - Merged community PR #1 (`tail-binds-statement`) enforcing strict `exact_tail` tip binding (`height`, `header_id`, `total_work`) with regression tests enabled in CI (`4/4` mutations rejected).
   - `scripts/renew_zisk_cpu.sh` reuses the published `6.58 MiB` `zisk-l1-1827840-prod128-archive.tar.gz` (14 immutable prefix L1 proofs covering `99.5%` of history) and proves shifting tail leaves on plain CPU via `cargo-zisk-cpu prove -m -y` (measured on 16-core CPU, `seg-00444b`, 0 GPU: **`608.97 s` / `10 min 09 s`**, **`43.12 GiB` peak RSS**, `0` swaps, `Exit 0`).

## Architecture

1. **Exact Rational 128-Bit Parameter Profile (`crates/ergo-nipopow-v2-core/src/profile.rs`, `scripts/certify_profiles.py`)**
   - `GRID_513`: 513 exact integer cap levels `ceil(2^(k/8))` (zero floating point).
   - `V2Production128`: `k_0 = 64`, `L = 896` (`7 × 128` EIP-37 epochs), `s = 210` (exact `15/64 = 23.4375%` fresh CQ ratio), `β = 3/4`, `Q_A = 2^128 + 1` (`982` draws/scale), `(A = 151, t = 40)`.
   - Every analytical term is `<= 2^-130` except `eps_early = (2^80 + 1)·(1/2 + 2^-37)^210 = 2^-130 · (1 + 3.06e-9) <= 2^-129.99`, and the total union sum is **`<= 2^-128.35 < 2^-128`** (conservative 6-term `<= 2^-128.13 < 2^-128`), machine-verified with zero floats in Python `fractions.Fraction`.
2. **Append-Only SHA-256 Work-Interval MMR (`mmr.rs`)**
   - Leaf preimages never include snapshot height `n`: appending blocks invalidates zero prior leaves, internal nodes, or segment proofs, and scales up to `n = 2^31 - 1` (~8,000 years).
   - Canonical deduplicated `MmrMultiproof` reduces audit sibling digests by ~75% (`62,863` siblings across `13,342` distinct opened headers).
3. **Associative Consensus Monoid & Constant-Depth (`d = 2`) Recursion (`monoid.rs`, `segment.rs`, `guests/`, `guests-zisk/`)**
   - Enforces all deterministic Ergo header rules matching reference node commit `8995ff243b140e7fe716bd3204423dd35690c2e4` (canonical VLQ codec, BLAKE2b-256 IDs, 3-mul witness-assisted secp256k1 point checks, height-to-era binding, all-era contextual DAA including EIP-37, Appendix B legacy envelope, and sliding modern bands).
   - `BootstrapStatement` certifies all 9 EIP-37 anchors and modern difficulty bands directly inside the Root STARK — zero unauthenticated context enters the light client.
4. **Heterogeneous Dual-Proof Envelope, WASM Light Verifier & State Proofs (`certificate.rs`, `state_proof.rs`, `crates/ergo-nipopow-v2-light/`, `host-aggregator/`)**
   - Jointly binds ZisK `v1.4.0-alpha` STIR and OpenVM `v2.1.0` SWIRL/WHIR inside `DualStructuralProof` before Fiat-Shamir audit sampling.
   - `ergo-nipopow-v2-aggregator` (`--no-default-features`, zero CUDA) verifies BOTH STARK proofs + 13,748-draw Autolykos audit + 8,196-header exact tail + full dual tamper suite.
   - `ergo-nipopow-v2-light` (`wasm32-unknown-unknown` & native CPU, zero prover SDK) verifies the ZisK STIR proof + audit + exact tail + gzip transport + `LightCheckpoint` plain-header continuation + Ergo AVL+ `ADProofs` & Scorex tx Merkle proofs.

## Measured Mainnet Results (`v0.4.0`, `n = 1,827,840`, extended live to `1,827,976`)

| Metric | Standalone ZisK STIR (`ZiskStirV14`) | Heterogeneous Dual-Proof (`DualZiskV14OpenVmV21`) |
| --- | ---: | ---: |
| Security level (`V2Production128`) | Strict 128-bit (`<= 2^-128.35`) | Strict 128-bit + dual-zkVM diversity |
| Path-independent reproducible VKs (`--remap-path-prefix`) | **3/3 ZisK ROM roots bit-for-bit** | **3/3 ZisK + 3/3 OpenVM zero-host-path** |
| Full genesis-to-root proving (ZisK, `2× RTX 5090`) | **`27 min 03 s`** (`449` leaves + `17` L1 + `1` Root + STIR) | + OpenVM `v2.1.0` depth-2 (`7m 35s` agg) |
| Incremental L1 + Root renewal (1 GPU, 99.5% reused) | `~30 s` (reusing 14 frozen L1 proofs) | **`23.25 s`** OpenVM + `~30 s` ZisK |
| Permissionless CPU-only leaf prove (0 GPU, 16-core CPU) | **`608.97 s`** (`10m 09s`, `43.12 GiB` peak RSS, `seg-00444b`) | — |
| Root structural proof size | **`245.96 KiB`** (`251,864 B`) | **`245.96 KiB`** + **`533.5 KiB`** |
| Bootstrap maturity lag (`b = 1,819,644`) | `8,196` blocks (**`11.49 days`**) | `8,196` blocks (**`11.49 days`**) |
| Exact-tail maturity lag (`h = 1,823,986`) | `3,854` blocks (**`5.39 days`**) | `3,854` blocks (**`5.39 days`**) |
| Total cold sync download (uncompressed) | **`7.29 MiB`** (`1.79%` of 407.07 MiB) | **`7.79 MiB`** (`1.91%` of 407.07 MiB) |
| **Total cold sync download (gzip-9 `.gz`)** | **`5.99 MiB`** (`1.47%` of 407.07 MiB) | **`6.23 MiB`** (`1.53%` of 407.07 MiB) |
| **Cold CPU-only verification (desktop CPU, 0 GPU)** | **`3.359–3.389 s`** (**`2 ms`** STARK) | **`3.535 s`** (**`224 ms`** both STARKs) |
| **Cold WebAssembly verification (live V8 / Node.js)** | **`4.574 s`** (`< 1 MiB` `.wasm.gz`, zero JS imports) | — |
| **Returning-user `extend-tail` (`+136` live blocks, 0 STARK)** | **`28.4 ms` V8 WASM** / `0.030–0.147 s` native | **`0.030–0.147 s`** native |
| **Live post-STARK block `1,827,976` AVL+ `ADProofs` + Tx Merkle** | **`27.6 ms` V8 WASM** / **`0.05 ms` state verify** | **`0.05 ms` state verify** (`2,828 B` ADProofs) |
| **Certified block `1,823,986` AVL+ `ADProofs` + `1,823,985` Tx Merkle** | **`0.06 ms`** (`2,809 B` ADProofs, `3/3` tampers rejected) | **`0.06 ms`** (`2,809 B` ADProofs, `3/3` tampers rejected) |
| Negative tamper checks & multi-peer fork selection | **PASS (fail-closed)** | **PASS on BOTH proofs (fail-closed)** |

## Release Artifacts (`v0.4.0` — 100% Path-Independent Reproducible Snapshot)

Mainnet 128-bit certificate bundles (raw + `.gz`, VKs, L1 renewal archive, and `SHA256SUMS.txt` on GitHub Releases `v0.4.0`):

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `ergo-mainnet-1827840-prod128-dual.npv2.bin` | 6,335,262 B (6.04 MiB) | `ed4f741ef4bf94c11bfed61d4f26500e60ef9b7d522fd77541009b660cd36356` |
| `ergo-mainnet-1827840-prod128-dual.npv2.bin.gz` | 5,176,961 B (4.94 MiB) | `0455f0be8e3d0526a9b0b5f4c86e6f8a824dc4e0934036d0b683b88de7801ba2` |
| `ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin` | 5,807,451 B (5.54 MiB) | `562cfa2100c6a1d74f09c669021d0d01bc2a6cdb2b4d3a34e2b042c0467c3767` |
| `ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin.gz` | 4,918,630 B (4.69 MiB) | `22aa9e474bda16c32acdd8a0d5cde0c273d85892af078f01f63a88f047ecca2b` |
| `tail-1819645-1827840.u32le` | 1,835,904 B (1.75 MiB) | `b0eb7b08b8b8d281b4cc2382f39da51f78d316c62cd048d52af4d795cadb76f3` |
| `tail-1819645-1827840.u32le.gz` | 1,360,716 B (1.30 MiB) | `753ed8a27a9e4dfbcd262e2eb8c0f75b453e704fb745f31e2dbdeaed9edd40e2` |
| `root-agg.vk` | 95,973 B (93.7 KiB) | `15d415ec0e8dc7910c771c0fc699b0ebec5a42512c595a8f5e9dcd962e6c1d2b` |
| `root-baseline.json` | 1,263 B | `4e1441e68c98cf3c99aaf5095ed79f5a1e4bd0ac88c785b6ad51e6a7e0a77d58` |
| `zisk-root-1827840-prod128-result.tar.gz` | 655,781 B (640.4 KiB) | `d4ff11eb1ed426f20569b1ee17cae27498bf78d88ecd2363e833f735c816a878` |
| `zisk-l1-1827840-prod128-archive.tar.gz` | 6,900,514 B (6.58 MiB) | `9d938e4ccee202bba45a21c9295be96df842d1d87a3c1c31ce20d74e09b0c218` |

## Quickstart: Verify on Your Own CPU or Live Inside V8 WebAssembly

```bash
# 1. Run all 14 workspace tests (core consensus, adversarial negatives, multi-peer fork selection,
#    mainnet 1,823,986 & live post-STARK 1,827,976 AVL+ ADProofs, Tx Merkle, and extend-tail)
cargo test --release

# 2. Build the executable wasm32-unknown-unknown cdylib (zero prover SDK, zero JS imports)
rustup target add wasm32-unknown-unknown
cargo build -p ergo-nipopow-v2-light --no-default-features --target wasm32-unknown-unknown --release

# 3. Re-verify exact rational 128-bit bounds (zero floating point)
python3 scripts/certify_profiles.py

# 4. Download v0.4.0 mainnet certificates, verify inside V8 WASM & native CLI, extend live & check ADProofs
mkdir -p release-assets && gh release download v0.4.0 -R a-shannon/ergo-nipopow-v2 -D release-assets
(cd release-assets && sha256sum -c SHA256SUMS.txt)

node wasm/verify_v8.mjs \
  target/wasm32-unknown-unknown/release/ergo_nipopow_v2_light.wasm \
  release-assets/ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin.gz \
  release-assets/tail-1819645-1827840.u32le.gz \
  crates/ergo-nipopow-v2-light/testdata/extension_1827841_1827976.u32le \
  crates/ergo-nipopow-v2-light/testdata/mainnet_1827976_live_state_proof.json

cargo run -p ergo-nipopow-v2-light --release -- verify-cert \
  --cert-bin release-assets/ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin.gz \
  --headers-u32le release-assets/tail-1819645-1827840.u32le.gz \
  --save-checkpoint ckpt-1827840.json

cargo run -p ergo-nipopow-v2-light --release -- verify-live-state-proof \
  --checkpoint-in ckpt-1827840.json \
  --new-headers-u32le crates/ergo-nipopow-v2-light/testdata/extension_1827841_1827976.u32le \
  --state-fixture-json crates/ergo-nipopow-v2-light/testdata/mainnet_1827976_live_state_proof.json

# 5. Full Dual-Proof cold CPU verification (verifies BOTH ZisK STIR & OpenVM SWIRL/WHIR + dual tamper suite)
cargo run --manifest-path host-aggregator/Cargo.toml --release --no-default-features -- verify-cert \
  --cert-bin release-assets/ergo-mainnet-1827840-prod128-dual.npv2.bin \
  --root-agg-vk release-assets/root-agg.vk \
  --root-baseline release-assets/root-baseline.json \
  --zisk-root-vk "11772000642296811191,2917608110684279903,7269122849900466967,12697094355253129467" \
  --headers-u32le release-assets/tail-1819645-1827840.u32le \
  --query-height 1823986

# 6. Independently reproduce all 3 ZisK ROM roots (+ OpenVM leaf .vmexe) bit-for-bit from source (0 GPU)
bash scripts/verify_reproducible_vks.sh
```

## Repository Layout

- `crates/ergo-nipopow-v2-core/` — `no_std` consensus header verification, append-only SHA-256 MMR, associative monoid, `V2Production128` profile, native Autolykos v1/v2 audit, `LightCheckpoint` & exact-tail verifier (with PR #1 tip-binding), Scorex Tx Merkle proofs, and adversarial negative tests.
- `crates/ergo-nipopow-v2-light/` — Minimal standalone zero-prover-SDK light-client verifier (native CPU + executable `wasm32-unknown-unknown` `cdylib`), transparent pure-Rust gzip transport, `extend-tail`, live post-STARK Ergo AVL+ `ADProofs` (`ergo_avltree_rust`) + Tx Merkle verification, and untrusted multi-peer fork selection (`compare-certs`).
- `wasm/verify_v8.mjs` — Zero-dependency Node.js V8 WebAssembly verifier runner & benchmark (executed live in CI).
- `web/` — Zero-backend, zero-npm browser WebAssembly light client (`index.html`, `nipopow-v2.js`, `worker.js`) with live plain-header `extend-tail` syncing against public Ergo nodes.
- `docs/EIP-NIPOPOW-V2-TRANSPORT.md` — Draft specification for opt-in read-only Ergo node REST/P2P serving of NiPoPoW V2 bundles.
- `docker/reproducible-zisk-vks.Dockerfile` — Pinned Ubuntu 24.04 + ZisK `v1.4.0-alpha` container for bit-for-bit VK reproduction.
- `crates/ergo-nipopow-v2-cli/` — Mainnet header verifier (`verify-mainnet`), bootstrap splitter, and ZisK/OpenVM input exporters.
- `guests-zisk/` — Pinned ZisK `v1.4.0-alpha` RV64IMA recursive guests (`leaf-segment`, `agg-l1`, `agg-root`) with committed `Cargo.lock` files.
- `guests/` — Pinned OpenVM `v2.1.0` RV32IM recursive guests (`leaf-segment`, `agg-l1`, `agg-root`) with committed `Cargo.lock` files.
- `host-aggregator/` — Depth-2 recursive aggregator (with automatic `--remap-path-prefix`), Dual-Proof assembler, and zero-CUDA CPU Dual-Proof verifier.
- `scripts/certify_profiles.py` — Pure exact-rational 128-bit parameter certification script.
- `scripts/verify_reproducible_vks.sh` — Deterministic `--remap-path-prefix` ELF & VK reproducibility verifier (reproduces all 3 live `v0.4.0` ZisK ROM roots + OpenVM leaf `.vmexe` bit-for-bit).
- `scripts/renew_zisk_cpu.sh` — Permissionless CPU-only (zero GPU) incremental renewal reusing the 14 frozen L1 prefix proofs.
- `scripts/run_zisk_mainnet128_dual_gpu.sh` — Reproducible multi-GPU ZisK `v1.4.0-alpha` full-mainnet prover script.
- [`WHITEPAPER-V2.md`](WHITEPAPER-V2.md) — Complete technical specification, mathematical bounds, benchmarks, and commitments.

## Status, Reproducibility & Security Notice

This repository is an open-source reference implementation published for independent verification, peer review, and Ergo ecosystem integration:
- `ergo-nipopow-v2-core`, `ergo-nipopow-v2-light`, and the pinned guest binaries have not yet undergone an independent external security audit, and ZisK `v1.4.0-alpha` external audits are ongoing (mitigated by heterogeneous dual-proving with audited OpenVM `v2.1.0`).
- **100% Build Reproducibility (`v0.4.0`):** Every verifying key and program commitment pinned in the live `v0.4.0` mainnet Dual-Proof snapshot is built from committed source and `Cargo.lock` files with `--remap-path-prefix` (zero host paths across all 6 guest ELFs). Anyone can reproduce all 3 ZisK ROM roots and the OpenVM leaf `.vmexe` bit-for-bit on any x86_64 Linux host or via `docker/reproducible-zisk-vks.Dockerfile`.
- Ergo node P2P/REST serving is not yet integrated.
