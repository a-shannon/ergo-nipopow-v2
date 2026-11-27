# Ergo NiPoPoW V2

**Strict 128-Bit Incremental Post-Quantum Certification of Ergo Header History**

A. Shannon · 27 November 2026 · MIT OR Apache-2.0

[![CI](https://github.com/a-shannon/ergo-nipopow-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/a-shannon/ergo-nipopow-v2/actions/workflows/ci.yml)

---

## Overview

**Ergo NiPoPoW V2** certifies Ergo's complete canonical header history from genesis (`1..=1,827,840`) at **strict 128-bit end-to-end post-quantum security** (`V2Production128`) with **zero hard fork, zero soft fork, zero miner change, zero trusted setup, and zero elliptic-curve pairing assumptions**.

All **1,827,840 canonical Ergo mainnet headers** (tip `20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`, `407.07 MiB` raw headers) have been proved end-to-end into a **Heterogeneous Dual-Proof `V2Certificate`** pairing two completely independent transparent post-quantum zkVMs over the **exact byte-identical `BootstrapStatement`** (`SHA-256 = e7981fbc64af4abdd38292792584f1d9850ee6fb293f12c27f2dead07a55edbc`):

- **Proof A — ZisK `v1.4.0-alpha`** (`RV64IMA`, `Goldilocks^3`, 256-bit `BLAKE3`, DEEP-ALI + **STIR `--minimal`**): **`243.27 KiB` (`249,112 B`)**, verified on pure CPU in **`2 ms`**. Full 7-year genesis-to-STIR run completed in **`30 min 30 s`** on `2× RTX 5090`.
- **Proof B — OpenVM `v2.1.0`** (`RV32IM`, `BabyBear^4`, `Poseidon2`, **SWIRL/WHIR**, zkSecurity audited & Lean-verified): **`533.5 KiB` (`546,306 B`)**. Incremental depth-2 renewal (delta L1 + Root) completes in **`27.44 s`** on a single RTX 4090 by reusing 99.5% of frozen history.

### What's New in `v0.3.0` (Zero Prover Liveness Cliff, WASM Light Verifier, Trustless AVL+ State Proofs & CPU Renewal)

1. **Standalone Zero-Prover-SDK Light Verifier + `wasm32-unknown-unknown` Target (`crates/ergo-nipopow-v2-light`):**
   - Pure-Rust verifier library and CLI with **zero OpenVM SDK, zero CUDA, and zero C++ dependencies** — compiles cleanly to both native CPU and **`wasm32-unknown-unknown`** (for browser extensions and mobile light wallets).
   - Transparent pure-Rust gzip transport reduces cold sync downloads by ~18–20%: **`6.24 MiB`** total (`Dual .gz` + `tail .gz`, `1.53%` of raw headers) or **`5.97 MiB`** (`ZisK STIR .gz` + `tail .gz`, `1.47%` of raw headers).
2. **Zero Prover Liveness Cliff — Indefinite Plain-Header Continuation (`LightCheckpoint` + `extend-tail`):**
   - After one initial cold sync, the verifier saves a **`5.6 KiB` `LightCheckpoint`** (`checkpoint_1827840.json`). Returning users **never need a STARK prover again**: they extend the checkpoint indefinitely using plain Ergo headers only (`~160 KiB/day` at 720 blocks/day).
   - Verified in CI on **136 real live Ergo mainnet blocks mined after `1,827,840`** (`1,827,841..=1,827,976`, `30,464 B`, crossing the real EIP-37 difficulty retarget `105028762 -> 105229481` at height `1,827,969`) in **`0.147 s`** with zero STARK download, plus isolated tamper rejections on parent link, EIP-37 `nBits`, and Autolykos v2 PoW nonce.
3. **End-to-End Trustless Ergo Mainnet AVL+ `ADProofs` & Tx Merkle Verification (`verify-state-proof`):**
   - Connects NiPoPoW V2 certified headers directly to Ergo's UTXO state layer so mobile/browser dApp clients (e.g., SigmaFi-style serverless apps) never need to trust an explorer/node API for balances or transaction inclusion.
   - Verified in CI against the real compressed mainnet certificate: replays the real **`2,809 B` `ADProofs`** AVL+ state transition (`ergo_avltree_rust::BatchAVLVerifier`) on certified mature block **`1,823,986`** (`stateRoot(1,823,985) -> stateRoot(1,823,986)` bit-for-bit, verifying `BLAKE2b-256(adProofs) == adProofsRoot`, box removals, and serialized created-box hashes) plus the real 5-level Scorex transaction Merkle inclusion proof on block **`1,823,985`** in **`0.09 ms`** (`3/3` isolated tamper checks rejected).
4. **Reproducible Verifying Keys & Permissionless CPU-Only Renewal (`scripts/verify_reproducible_vks.sh`, `scripts/renew_zisk_cpu.sh`):**
   - All 6 guest `Cargo.lock` files (`guests-zisk/*` and `guests/*`) are now committed and `scripts/verify_reproducible_vks.sh` applies deterministic `--remap-path-prefix` remapping (verified to strip 100% of host paths and reproduce bit-for-bit identical ZisK ROM roots across independent directories).
   - `scripts/renew_zisk_cpu.sh` reuses the published `6.57 MiB` `zisk-l1-1827840-prod128-archive.tar.gz` (14 immutable L1 proofs covering `99.5%` of history) and proves shifting tail leaves on a plain CPU using `cargo-zisk-cpu prove -m -y` (zero GPU). Measured locally on a 16-core CPU (`seg-00444b`, 63 headers): **`608.97 s` (`10 min 09 s`)**, **`43.12 GiB` peak RSS**, zero swaps, verified `Exit 0`.

## Architecture

1. **Exact Rational 128-Bit Parameter Profile (`crates/ergo-nipopow-v2-core/src/profile.rs`, `scripts/certify_profiles.py`)**
   - `GRID_513`: 513 exact integer cap levels `ceil(2^(k/8))` (zero floating point).
   - `V2Production128`: `k_0 = 64`, `L = 896` (`7 × 128` EIP-37 epochs), `s = 210` (exact `15/64 = 23.4375%` fresh CQ ratio), `β = 3/4`, `Q_A = 2^128 + 1` (`982` draws/scale), `(A = 151, t = 40)`.
   - Every analytical term `<= 2^-130` and total union sum **`<= 2^-128.35 < 2^-128`**, machine-verified with zero floats in Python `fractions.Fraction`.
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

## Measured Mainnet Results (`n = 1,827,840`, extended live to `1,827,976`)

| Metric | Standalone ZisK STIR (`ZiskStirV14`) | Heterogeneous Dual-Proof (`DualZiskV14OpenVmV21`) |
| --- | ---: | ---: |
| Security level (`V2Production128`) | Strict 128-bit (`<= 2^-128.35`) | Strict 128-bit + dual-zkVM diversity |
| Full genesis-to-root proving (ZisK, `2× RTX 5090`) | **`30 min 30 s`** (`449` leaves + `17` L1 + `1` Root + STIR) | + OpenVM `v2.1.0` depth-2 witness |
| Incremental L1 + Root renewal (1 GPU, 99.5% reused) | `~30 s` (reusing 14 frozen L1 proofs) | **`27.44 s`** OpenVM + `~30 s` ZisK |
| Permissionless CPU-only leaf prove (0 GPU, 16-core CPU) | **`608.97 s`** (`10m 09s`, `43.12 GiB` peak RSS, `seg-00444b`) | — |
| Root structural proof size | **`243.27 KiB`** (`249,112 B`) | **`243.27 KiB`** + **`533.5 KiB`** |
| Bootstrap maturity lag (`b = 1,819,644`) | `8,196` blocks (**`11.49 days`**) | `8,196` blocks (**`11.49 days`**) |
| Exact-tail maturity lag (`h = 1,823,986`) | `3,854` blocks (**`5.39 days`**) | `3,854` blocks (**`5.39 days`**) |
| Total cold sync download (uncompressed) | **`7.27 MiB`** (`1.79%` of 407.07 MiB) | **`7.80 MiB`** (`1.92%` of 407.07 MiB) |
| **Total cold sync download (gzip-9 `.gz`)** | **`5.97 MiB`** (`1.47%` of 407.07 MiB) | **`6.24 MiB`** (`1.53%` of 407.07 MiB) |
| **Cold CPU-only verification (desktop CPU, 0 GPU)** | **`3.274–3.462 s`** (**`2 ms`** STARK) | **`3.481–3.508 s`** (**`195–197 ms`** both STARKs) |
| **Returning-user `extend-tail` (`+136` live blocks, 0 STARK)** | **`0.147 s`** (`30.5 KiB`, crosses EIP-37 retarget) | **`0.147 s`** (`30.5 KiB`, crosses EIP-37 retarget) |
| **Mainnet AVL+ `ADProofs` (`1,823,986`) + Tx Merkle (`1,823,985`)** | **`0.09 ms`** (`2,809 B` ADProofs, `3/3` tampers rejected) | **`0.09 ms`** (`2,809 B` ADProofs, `3/3` tampers rejected) |
| Negative tamper checks | **PASS (fail-closed)** | **PASS on BOTH proofs (fail-closed)** |

## Release Artifacts (GitHub Releases)

Mainnet 128-bit certificate bundles (`v0.2.0` raw + `v0.3.0` `.gz` compressed bundles & `SHA256SUMS.txt`):

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `ergo-mainnet-1827840-prod128-dual.npv2.bin` | 6,344,950 B (6.05 MiB) | `49a561f55a8a7624f3f4a5d57ea32cdba6e0f37b78c65e9777bf587ab7afc845` |
| `ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin` | 5,792,092 B (5.52 MiB) | `ca047af2db8fb68747f6e6e3745bb2dd21c9d6dc183126b4e975e81b258e5af1` |
| `tail-1819645-1827840.u32le` | 1,835,904 B (1.75 MiB) | `b0eb7b08b8b8d281b4cc2382f39da51f78d316c62cd048d52af4d795cadb76f3` |
| `zisk-root-1827840-prod128-result.tar.gz` | 653,471 B (638.2 KiB) | `a028cab74ee2fad1a9956fe368d301122de07de059f1a8060dca8b5ef286c55d` |
| `zisk-l1-1827840-prod128-archive.tar.gz` | 6,887,517 B (6.57 MiB) | `06ba502525456f801759c812faa8516682725176c8c3f9801d5ff090f0eee10d` |

## Quickstart: Verify on Your Own CPU (or Build to WASM32)

```bash
# 1. Run all 12 workspace tests (core consensus, adversarial negatives, real mainnet 1,823,986 AVL+ ADProofs,
#    real mainnet 1,823,985 Tx Merkle, and real live 1,827,840 -> 1,827,976 extend-tail crossing EIP-37 retarget)
cargo test --release

# 2. Verify the minimal standalone light verifier compiles cleanly to wasm32-unknown-unknown (zero prover SDK)
rustup target add wasm32-unknown-unknown
cargo build -p ergo-nipopow-v2-light --no-default-features --target wasm32-unknown-unknown --release

# 3. Re-verify exact rational 128-bit bounds (zero floating point)
python3 scripts/certify_profiles.py

# 4. Download mainnet certificates, cold-verify with minimal light CLI, extend past 1,827,840 & verify AVL+ state proofs
mkdir -p release-assets && gh release download v0.2.0 -R a-shannon/ergo-nipopow-v2 -D release-assets
cargo run -p ergo-nipopow-v2-light --release -- verify-cert \
  --cert-bin release-assets/ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin \
  --headers-u32le release-assets/tail-1819645-1827840.u32le \
  --save-checkpoint ckpt-1827840.json
cargo run -p ergo-nipopow-v2-light --release -- extend-tail \
  --checkpoint-in ckpt-1827840.json \
  --new-headers-u32le crates/ergo-nipopow-v2-light/testdata/extension_1827841_1827976.u32le \
  --checkpoint-out ckpt-1827976.json
cargo run -p ergo-nipopow-v2-light --release -- verify-state-proof \
  --cert-bin release-assets/ergo-mainnet-1827840-prod128-dual.npv2.bin \
  --headers-u32le release-assets/tail-1819645-1827840.u32le \
  --state-fixture-json crates/ergo-nipopow-v2-light/testdata/mainnet_1823986_state_proof.json

# 5. Full Dual-Proof cold CPU verification (verifies BOTH ZisK STIR & OpenVM SWIRL/WHIR + dual tamper suite)
cargo run --manifest-path host-aggregator/Cargo.toml --release --no-default-features -- verify-cert \
  --cert-bin release-assets/ergo-mainnet-1827840-prod128-dual.npv2.bin \
  --root-agg-vk release-assets/root-agg.vk \
  --root-baseline release-assets/root-baseline.json \
  --zisk-root-vk "2061927828237341284,1907988207398174607,15624447174404746195,12050011039068599532" \
  --headers-u32le release-assets/tail-1819645-1827840.u32le \
  --query-height 1823986
```

## Repository Layout

- `crates/ergo-nipopow-v2-core/` — `no_std` consensus header verification, append-only SHA-256 MMR, associative monoid, `V2Production128` profile, native Autolykos v1/v2 audit, `LightCheckpoint` & exact-tail verifier, Scorex Tx Merkle proofs, and adversarial negative tests.
- `crates/ergo-nipopow-v2-light/` — Minimal standalone zero-prover-SDK light-client verifier (native CPU + `wasm32-unknown-unknown`), transparent pure-Rust gzip transport, `extend-tail`, and real-mainnet Ergo AVL+ `ADProofs` (`ergo_avltree_rust`) + Tx Merkle verification.
- `crates/ergo-nipopow-v2-cli/` — Mainnet header verifier (`verify-mainnet`), bootstrap splitter, and ZisK/OpenVM input exporters.
- `guests-zisk/` — Pinned ZisK `v1.4.0-alpha` RV64IMA recursive guests (`leaf-segment`, `agg-l1`, `agg-root`) with committed `Cargo.lock` files.
- `guests/` — Pinned OpenVM `v2.1.0` RV32IM recursive guests (`leaf-segment`, `agg-l1`, `agg-root`) with committed `Cargo.lock` files.
- `host-aggregator/` — Depth-2 recursive aggregator, Dual-Proof assembler, and zero-CUDA CPU Dual-Proof verifier.
- `scripts/certify_profiles.py` — Pure exact-rational 128-bit parameter certification script.
- `scripts/verify_reproducible_vks.sh` — Deterministic `--remap-path-prefix` ZisK ELF & ROM-root reproducibility check.
- `scripts/renew_zisk_cpu.sh` — Permissionless CPU-only (zero GPU) incremental renewal reusing the 14 frozen L1 prefix proofs.
- `scripts/run_zisk_mainnet128_dual_gpu.sh` — Reproducible multi-GPU ZisK `v1.4.0-alpha` full-mainnet prover script.
- [`WHITEPAPER-V2.md`](WHITEPAPER-V2.md) — Complete technical specification, mathematical bounds, benchmarks, and commitments.

## Status, Reproducibility & Security Notice

This repository is an open-source reference implementation published for independent verification, peer review, and Ergo ecosystem integration:
- `ergo-nipopow-v2-core` and its pinned guest binaries have not yet undergone an independent external security audit, and ZisK `v1.4.0-alpha` external audits are ongoing (mitigated by heterogeneous dual-proving with audited OpenVM `v2.1.0`).
- **Build reproducibility transparency:** The initial `v0.2.0` mainnet proof snapshot (`n = 1,827,840`) was built before `--remap-path-prefix` was added, which caused Rust panic `.rodata` strings in `leaf-segment` and `agg-root` to retain build-host paths (while `agg-l1` reproduces its `v0.2.0` ROM root bit-for-bit across arbitrary directories once `Cargo.lock` is pinned). Starting in `v0.3.0`, all 6 guest `Cargo.lock` files are committed and `scripts/verify_reproducible_vks.sh` enforces `--remap-path-prefix`, verified to eliminate 100% of host paths and reproduce bit-for-bit identical ZisK ROM roots across independent directories for future proving and renewal campaigns.
- Ergo node P2P/REST serving is not yet integrated.
