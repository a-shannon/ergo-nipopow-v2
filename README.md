# Ergo NiPoPoW V2

**Strict 128-Bit Incremental Post-Quantum Certification of Ergo Header History**

A. Shannon · 26 November 2026 · MIT OR Apache-2.0

[![CI](https://github.com/a-shannon/ergo-nipopow-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/a-shannon/ergo-nipopow-v2/actions/workflows/ci.yml)

---

## Overview

**Ergo NiPoPoW V2** certifies Ergo's complete canonical header history from genesis (`1..=1,827,840`) at **strict 128-bit end-to-end post-quantum security** (`V2Production128`) with **zero hard fork, zero soft fork, zero miner change, zero trusted setup, and zero elliptic-curve pairing assumptions**.

All **1,827,840 canonical Ergo mainnet headers** (tip `20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`, `407.07 MiB` raw headers) have been proved end-to-end into a **Heterogeneous Dual-Proof `V2Certificate`** pairing two completely independent transparent post-quantum zkVMs over the **exact byte-identical `BootstrapStatement`** (`SHA-256 = e7981fbc64af4abdd38292792584f1d9850ee6fb293f12c27f2dead07a55edbc`):

- **Proof A — ZisK `v1.4.0-alpha`** (`RV64IMA`, `Goldilocks^3`, 256-bit `BLAKE3`, DEEP-ALI + **STIR `--minimal`**): **`243.27 KiB` (`249,112 B`)**, verified on pure CPU in **`2 ms`**. Full 7-year genesis-to-STIR run completed in **`30 min 30 s`** on `2× RTX 5090`.
- **Proof B — OpenVM `v2.1.0`** (`RV32IM`, `BabyBear^4`, `Poseidon2`, **SWIRL/WHIR**, zkSecurity audited & Lean-verified): **`533.5 KiB` (`546,306 B`)**. Incremental depth-2 renewal (delta L1 + Root) completes in **`27.44 s`** on a single RTX 4090 by reusing 99.5% of frozen history.

A witness-free, zero-CUDA, pure-Rust CPU light client downloads **`7.80 MiB`** (`6.05 MiB` Dual-Proof certificate + `1.75 MiB` exact tail, or **`7.27 MiB`** for standalone ZisK STIR — `< 2%` of raw headers) and verifies all 1,827,840 blocks in **`3.508 s`** (`3.462 s` standalone ZisK STIR), certifying mature block **`h = 1,823,986`**.

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
4. **Heterogeneous Dual-Proof Envelope & CPU Light Client (`certificate.rs`, `host-aggregator/`)**
   - Jointly binds ZisK `v1.4.0-alpha` STIR and OpenVM `v2.1.0` SWIRL/WHIR inside `DualStructuralProof` before Fiat-Shamir audit sampling.
   - Zero-CUDA CPU verifier (`--no-default-features`) validates both proofs, the 13,748-draw Autolykos v1/v2 PoW audit, the 8,196-header exact tail, and runs an isolated fail-closed tamper suite.

## Measured Mainnet Results (`n = 1,827,840`)

| Metric | Standalone ZisK STIR (`ZiskStirV14`) | Heterogeneous Dual-Proof (`DualZiskV14OpenVmV21`) |
| --- | ---: | ---: |
| Security level (`V2Production128`) | Strict 128-bit (`<= 2^-128.35`) | Strict 128-bit + dual-zkVM diversity |
| Full genesis-to-root proving (ZisK, `2× RTX 5090`) | **`30 min 30 s`** (`449` leaves + `17` L1 + `1` Root + STIR) | + OpenVM `v2.1.0` depth-2 witness |
| Incremental L1 + Root renewal (99.5% history reused) | `~30 s` (reusing 14 frozen L1 proofs) | **`27.44 s`** OpenVM + `~30 s` ZisK |
| Root structural proof size | **`243.27 KiB`** (`249,112 B`) | **`243.27 KiB`** + **`533.5 KiB`** |
| Bootstrap maturity lag (`b = 1,819,644`) | `8,196` blocks (**`11.49 days`**) | `8,196` blocks (**`11.49 days`**) |
| Exact-tail maturity lag (`h = 1,823,986`) | `3,854` blocks (**`5.39 days`**) | `3,854` blocks (**`5.39 days`**) |
| Total cold sync download (cert + exact tail) | **`7.27 MiB`** (`1.79%` of 407.07 MiB) | **`7.80 MiB`** (`1.92%` of 407.07 MiB) |
| **Cold CPU-only verification (0 GPU)** | **`3.462 s`** (**`2 ms`** STARK + `2.14 s` audit + `1.27 s` tail) | **`3.508 s`** (**`195 ms`** 2 STARKs + `2.04 s` audit + `1.23 s` tail) |
| Negative tamper checks | **PASS (fail-closed)** | **PASS on BOTH proofs (fail-closed)** |

## Release `v0.2.0` Artifacts (GitHub Releases)

Download from the [`v0.2.0` release](https://github.com/a-shannon/ergo-nipopow-v2/releases/tag/v0.2.0):

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `ergo-mainnet-1827840-prod128-dual.npv2.bin` | 6,344,950 B (6.05 MiB) | `49a561f55a8a7624f3f4a5d57ea32cdba6e0f37b78c65e9777bf587ab7afc845` |
| `ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin` | 5,792,092 B (5.52 MiB) | `ca047af2db8fb68747f6e6e3745bb2dd21c9d6dc183126b4e975e81b258e5af1` |
| `tail-1819645-1827840.u32le` | 1,835,904 B (1.75 MiB) | `b0eb7b08b8b8d281b4cc2382f39da51f78d316c62cd048d52af4d795cadb76f3` |
| `zisk-root-1827840-prod128-result.tar.gz` | 653,471 B (638.2 KiB) | `a028cab74ee2fad1a9956fe368d301122de07de059f1a8060dca8b5ef286c55d` |
| `zisk-l1-1827840-prod128-archive.tar.gz` | 6,887,517 B (6.57 MiB) | `06ba502525456f801759c812faa8516682725176c8c3f9801d5ff090f0eee10d` |

## Quickstart: Verify on Your Own CPU in 3.5 Seconds

```bash
# 1. Run core unit tests + isolated single-fault adversarial negative suite
cargo test --release

# 2. Re-verify exact rational 128-bit bounds (zero floating point)
python3 scripts/certify_profiles.py

# 3. Download v0.2.0 release assets and verify SHA-256 digests
mkdir -p release-assets && cd release-assets
gh release download v0.2.0 -R a-shannon/ergo-nipopow-v2
sha256sum -c SHA256SUMS.txt
cd ..

# 4. Cold-verify the Heterogeneous Dual-Proof 128-bit certificate (CPU-only, zero GPU, + dual tamper suite)
cargo run --manifest-path host-aggregator/Cargo.toml --release --no-default-features -- verify-cert \
  --cert-bin release-assets/ergo-mainnet-1827840-prod128-dual.npv2.bin \
  --root-agg-vk release-assets/root-agg.vk \
  --root-baseline release-assets/root-baseline.json \
  --zisk-root-vk "2061927828237341284,1907988207398174607,15624447174404746195,12050011039068599532" \
  --headers-u32le release-assets/tail-1819645-1827840.u32le \
  --query-height 1823986

# 5. Cold-verify the standalone 128-bit ZisK STIR certificate (2 ms STARK + audit + tail = 3.46 s CPU)
cargo run --manifest-path host-aggregator/Cargo.toml --release --no-default-features -- verify-cert \
  --cert-bin release-assets/ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin \
  --zisk-root-vk "2061927828237341284,1907988207398174607,15624447174404746195,12050011039068599532" \
  --headers-u32le release-assets/tail-1819645-1827840.u32le \
  --query-height 1823986
```

## Repository Layout

- `crates/ergo-nipopow-v2-core/` — `no_std` consensus header verification, append-only SHA-256 MMR, associative monoid, `V2Production128` profile, native Autolykos v1/v2 audit & exact-tail verifier, `DualStructuralProof` envelope, and adversarial negative tests.
- `crates/ergo-nipopow-v2-cli/` — Mainnet header verifier (`verify-mainnet`), bootstrap splitter, and ZisK/OpenVM input exporters.
- `guests-zisk/` — Pinned ZisK `v1.4.0-alpha` RV64IMA recursive guests (`leaf-segment`, `agg-l1`, `agg-root`).
- `guests/` — Pinned OpenVM `v2.1.0` RV32IM recursive guests (`leaf-segment`, `agg-l1`, `agg-root`).
- `host-aggregator/` — Depth-2 recursive aggregator, Dual-Proof assembler, and standalone zero-CUDA CPU verifier.
- `scripts/certify_profiles.py` — Pure exact-rational 128-bit parameter certification script.
- `scripts/run_zisk_mainnet128_dual_gpu.sh` — Reproducible multi-GPU ZisK `v1.4.0-alpha` full-mainnet prover script.
- [`WHITEPAPER-V2.md`](WHITEPAPER-V2.md) — Complete technical specification, mathematical bounds, benchmarks, and commitments.

## Status & Security Notice

This repository is an open-source reference implementation published for independent verification, peer review, and Ergo ecosystem integration. `ergo-nipopow-v2-core` and its pinned guest binaries have not yet undergone an independent external security audit, ZisK `v1.4.0-alpha` external audits are ongoing (mitigated by heterogeneous dual-proving with audited OpenVM `v2.1.0`), and Ergo node P2P/REST serving is not yet integrated.
