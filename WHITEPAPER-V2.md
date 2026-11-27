# Ergo NiPoPoW V2
## Strict 128-Bit Incremental Post-Quantum Certification of Ergo Header History

**A. Shannon** · 27 November 2026 · Version 0.4.1

---

### Abstract

An Ergo light client presented with competing header histories must identify a mature header on the valid chain of greatest cumulative proof-of-work. Classical superblock proofs (NiPoPoW V1) compare sparse interlink subchains without executing every hidden contextual difficulty transition between visible superblocks. **Ergo NiPoPoW V2** certifies the complete deterministic Ergo header history from genesis—canonical VLQ serialization, `BLAKE2b-256` header identifiers, parent links, strictly increasing timestamps, height-bound Autolykos era selectors, canonical secp256k1 point membership, all-era contextual difficulty adjustment (initial era, Autolykos v2 activation resets, legacy 1,024-block linear regression, and EIP-37 128-block clamped averages), cumulative work intervals, and maturity eligibility guards—while verifying native Autolykos proof-of-work at work-weighted geometric audit coordinates and across a short exact recent tail.

Any untrusted peer can generate and renew certificates from existing mainnet headers with **zero hard fork, zero soft fork, zero miner change, zero trusted setup, and zero elliptic-curve pairing assumptions**.

Five architectural properties make full-history 128-bit verification practical on commodity hardware:

1. **Strict 128-bit end-to-end parameter certification (`V2Production128`):** Every analytical error term is machine-certified `<= 2^-130` except the early-tag survival term `eps_early = (2^80 + 1)·(1/2 + 2^-37)^210 = 2^-130 · (1 + 3.06e-9) <= 2^-129.99` (all bounds verified in pure exact rational arithmetic in `scripts/certify_profiles.py`, zero floating point), with total analytical union sum **`<= 2^-128.35 < 2^-128`** (conservative 6-term `<= 2^-128.13 < 2^-128`).
2. **Append-only SHA-256 Work-Interval MMR:** Leaf preimages commit only to `(profile32, height, W(i-1), W(i), raw_header)` and never hash the snapshot height `n`. Appending blocks invalidates zero prior leaves, internal nodes, or segment proofs, and removes fixed-depth height ceilings (`n < 2^31`, ~8,000 years of Ergo blocks). Canonical deduplicated multiproofs reduce audit sibling digests by ~75%.
3. **Exact associative segment-transition monoid & constant-depth (`d = 2`) recursion:** The entire deterministic Ergo consensus header relation and all three maturity zones decompose into an exact associative monoid over contiguous 4,096-header segments. Segments prove in parallel and fold at constant depth `d = 2` (capacity `64^2 × 4,096 = 16,777,216` headers, ~64 years) with compile-time child-program VK pinning at every level.
4. **Heterogeneous Dual-Proof structural certification (`ZisK v1.4.0-alpha` STIR + `OpenVM v2.1.0` SWIRL/WHIR):** The exact byte-identical `BootstrapStatement` is proved simultaneously by two completely independent transparent post-quantum zkVMs over distinct ISAs, finite fields, hash functions, and polynomial commitment schemes, jointly bound before deriving the Fiat-Shamir work audit.
5. **Zero unauthenticated light-client context:** `BootstrapStatement` embeds the STARK-certified bootstrap timestamp, difficulty, all 9 EIP-37 DAA anchors, and all modern sliding-window difficulty bands at bootstrap height `b`. The exact-tail verifier consumes zero unauthenticated side-channel data.

**Measured end-to-end mainnet results across all 1,827,840 canonical Ergo mainnet headers** (tip `20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`, 407.07 MiB raw headers, **`v0.4.0` 100% path-independent `--remap-path-prefix` snapshot**):
- **Proof A (`ZisK v1.4.0-alpha`, `RV64IMA`, `Goldilocks^3`, 256-bit `BLAKE3`, STIR `--minimal`, 128-bit `ethereum/soundcalc` JBR):** All 449 leaves (`1,349 s`) + 17 Level-1 recursive proofs (`255 s`) + 1 Level-2 Root (`19 s`) + STIR wrap (`< 1 s`) = **`27 min 03 s`** total on `2× RTX 5090`, producing one **`245.96 KiB` (`251,864 B`)** root proof verified on pure CPU in **`2 ms`**. All 3 guest ROM roots reproduce bit-for-bit from source via `scripts/verify_reproducible_vks.sh` and `docker/reproducible-zisk-vks.Dockerfile`.
- **Proof B (`OpenVM v2.1.0`, `RV32IM`, `BabyBear^4`, `Poseidon2`, SWIRL/WHIR, zkSecurity audited & Lean-verified):** All 449 leaves + 10 Level-1 proofs (`298.5 s`) + 1 Level-2 Root (`11.22 s`), producing one **`533.5 KiB` (`546,289 B`)** proof over the **exact byte-identical `BootstrapStatement`** (`SHA-256 = e7981fbc64af4abdd38292792584f1d9850ee6fb293f12c27f2dead07a55edbc`), with **`23.25 s`** incremental L1+Root renewal reusing 99.5% of frozen history and zero host paths across all 3 compiled guest ELFs.
- **Cold witness-free CPU & live V8 WebAssembly light-client verification (zero CUDA, zero full history):**
  - **Dual-Proof (`6.04 MiB` raw / `4.94 MiB` `.gz` cert + `1.75 MiB` raw / `1.30 MiB` `.gz` exact tail = `6.23 MiB` `.gz`, `1.53%` of raw headers):** **`3.535 s`** total (`0.224 s` both STARKs + `2.029 s` 13,748-draw audit + `1.233 s` 8,196-header exact tail certifying mature height **`h = 1,823,986`**).
  - **Standalone ZisK STIR (`5.54 MiB` raw / `4.69 MiB` `.gz` cert + `1.30 MiB` `.gz` exact tail = `5.99 MiB` `.gz`, `1.47%`):** **`3.359–3.389 s`** native CPU (**`0.002 s`** STIR STARK) and **`4.574 s`** live inside **V8 WebAssembly** (`ergo_nipopow_v2_light.wasm`, `< 1 MiB` gzip-9, zero JS imports).
  - **Fail-closed tamper resistance & untrusted multi-peer fork selection:** All isolated single-fault tamper tests across both proofs, statement fields, MMR siblings, tail PoW, exact-tail tip binding (`PR #1`), live post-STARK block `1,827,976` `ADProofs`, and EIP-37 anchors are rejected (`NEGATIVE_TAMPER_SUITE_PASS` + `MULTI_PEER_SELECT_BEST_PASS`).

---

### 1. Security Model, Compatibility, and Chain Selection

The protocol gap addressed by NiPoPoW V2 is Ergo's full contextual difficulty transition history. A sparse superblock/interlink proof does not execute every intermediate difficulty retarget between visible superblocks. NiPoPoW V2 proves those deterministic consensus rules over the entire canonical header chain from genesis to tip, leaving native Autolykos v1/v2 proof-of-work verification at work-weighted geometric audit coordinates and across an exact modern continuation tail.

A V2 light client runs three isolated verification stages:

1. **Structural STARK verifier:** Verifies the constant-depth transparent post-quantum structural proof(s) binding `SHA-256(bincode(BootstrapStatement))`—committing to profile `S`, tip height `n`, tip ID, tip timestamp, total work `W_P`, bagged MMR root `R_P`, bootstrap height `b`, bootstrap ID/timestamp/difficulty, all 9 EIP-37 epoch anchors at `b`, all modern sliding-window difficulty bands at `b`, and the exact-tail 4-integer summary `(W_B, A_B, T_1, T_2)`—to a valid genesis-rooted deterministic Ergo header chain.
2. **Pre-audit native work verifier:** Derives geometric work coordinates deterministically from `SHA-512("Ergo-NiPoPoW-V2/audit/v2/1\0" || BE64(|x|) || x || BE64(|pi_s|) || pi_s)`, validates the canonical deduplicated MMR multiproof against `R_P`, enforces `work_hi - work_lo == D(raw_header)` and height-to-era binding, and checks full native Autolykos v1/v2 PoW on every opened header.
3. **Exact recent-chain verifier & deterministic fork-choice comparator:** Validates every modern header in `(b, n]` natively using only the STARK-certified anchors and bands inside `BootstrapStatement` (canonical codec, parent ancestry, strict timestamps, contextual EIP-37 DAA, native Autolykos v2 PoW, and exact-tail maturity guard). Among all admitted candidates matching the requested `(profile, query_height)`, the client selects the candidate with greatest certified cumulative work, breaking equal-work ties by lexicographically smallest canonical object bytes and returning `NO_RESULT` when no candidate is admitted.

The deterministic consensus rules match Ergo reference node commit `8995ff243b140e7fe716bd3204423dd35690c2e4` (`HeaderSerializer.scala`, `DifficultyAdjustment.scala`, `DifficultySerializer.scala`, `HeadersProcessor.scala`, `AutolykosPowScheme.scala`, `ExtensionValidator.scala`).

---

### 2. Parameter Specification & Exact Rational 128-Bit Certification (`V2Production128`)

All work quantities are exact nonnegative integers in the zero-genesis coordinate (`W_P(1) = 0`, `W_P(i) = sum_{r=2..i} D_P(r)`). Difficulty caps are quantized on a fine 513-level exact integer geometric grid `GRID_513[k] = ceil(2^(k/8))` (`k = 0..=512`, precomputed via exact integer 8th-root bounds `g^8 >= 2^k` and `(g-1)^8 < 2^k`, capping rounding inflation at `2^(1/8) ≈ 1.0905×` instead of `2.0×`).

Every inequality in `V2Production128` (`ProfileId::V2Production128 = 3`) is independently certified in pure exact rational arithmetic (`fractions.Fraction`, zero floating-point operations, provable Taylor/artanh enclosures rounded strictly in the conservative direction) by `scripts/certify_profiles.py`:

| Parameter / Bound | Certified `V2Production128` Value | Exact Meaning / Proof Role |
| --- | ---: | --- |
| Height ceiling `n` | `< 2^31` | ~8,000 years of Ergo blocks |
| Difficulty-cap grid | `GRID_513`: `ceil(2^(k/8))` | 513 exact integer levels; `1.0905×` max rounding |
| Common-prefix depth `k_0` | `64` | Temporal common-prefix premise `ε_CP` |
| Recent window `L`; fresh classes `s` | **`896`; `210`** | Exact `15/64 = 23.4375%` fresh CQ ratio; `896 = 7 × 128` EIP-37 epochs |
| Modern origin start `s_L = 844,672 + k_0 + L` | **`845,632`** | Exact boundary after EIP-37 activation window |
| Genuine sampled-work fraction `β` | `3/4` | Drift rate `J_β = β·θ - η` |
| Resource coefficients `(a, h, b, ν, ω)` | `(4/15, (3/4)(1-2^-32), 16/15, 1/20, 16)` | Mining-clock resource model |
| Exponential parameter `e^θ` | `27/20 = 1.35` | `p_* · e^η <= 1` (`p_* = 1/2 + 2^-37`) |
| Legacy v1 work allowance `b_1` | `9,072` | Exact `ceil(T_1 / U_global)` on `GRID_513` |
| Audit query budget `Q_A`; draws/scale | **`2^128 + 1`; `982`** | **`ε_audit <= 2^-130.30`** |
| Autolykos v2 rank bound `(A, t)` | **`(151, 40)`** | **`ε_rank <= 2^-131.63`** (`U·Q·2^-151 < 1/60`) |
| Early-tag survival (`Q = 2^80 + 1`) | `s = 210` | **`ε_early <= 2^-130.00`** |
| Sampled maturities `(v1, early_v2, modern)` | **`(40,099; 21,769; 4,142)`** | **`ε_global_race <= 2^-131.15`**, **`ε_local_race <= 2^-131.20`** |
| Exact-tail maturities `(v1, early_v2, modern)` | **`(19,879; 10,807; 2,083)`** | **`ε_global_race <= 2^-131.39`**, **`ε_local_race <= 2^-131.36`** |
| **Total analytical union sum (5 terms)** | **`<= 2^-128.35 < 2^-128`** | Conservative 6-term sum **`<= 2^-128.14 < 2^-128`** |

On the live 1,827,840-header mainnet snapshot, `V2Production128` yields a real bootstrap checkpoint at **`b = 1,819,644`** (`8,196` blocks / **`11.49 days`** behind tip) and latest exact-tail mature query at **`h = 1,823,986`** (`3,854` blocks / **`5.39 days`** behind tip; `h + 1 = 1,823,987` is rejected).

---

### 3. Append-Only SHA-256 Work-Interval MMR & Deduplicated Multiproof

Header history is committed in an **append-only SHA-256 Merkle Mountain Range (MMR)** whose leaf preimages are completely independent of the current tip height `n`:

```text
profile32     = SHA-256("ergo-nipopow-v2/mmr-profile/v1\0" || GENESIS_ID)
leaf(i)       = SHA-256("L" || profile32 || BE32(i) || BE224(W_P(i-1)) || BE224(W_P(i)) || BE16(len(raw_i)) || raw_i)   (i >= 2, pos = i - 2)
node(l, idx)  = SHA-256("N" || BE8(l) || BE64(idx) || left32 || right32)                                                (l >= 1)
mmr_root(n)   = SHA-256("R" || profile32 || BE32(n) || BE8(k) || peak_0 || ... || peak_{k-1})
```

- **Zero historical invalidation:** Extending the chain by `Δn` blocks appends `Δn` leaves and merges `O(log n)` peaks; 100% of earlier leaves, internal nodes, and proved segments remain byte-identical.
- **Collision binding:** The tip height `n` is committed at `mmr_root(n)` and inside `BootstrapStatement`. Two distinct valid openings at the same position imply a SHA-256 collision.
- **Canonical deduplicated multiproof (`MmrMultiproof`):** Given sorted distinct opened leaf indices `pos_0 < ... < pos_{K-1}`, any internal node whose left and right children are both derived from opened leaves emits zero sibling hashes. Only boundary siblings (in canonical level-ascending, index-ascending order) and untouched peak digests are transmitted. On the 1,827,840-header `V2Production128` certificate (`13,748` draws, `13,342` distinct opened headers), deduplication compresses sibling digests by **~75%** to **`62,863` siblings**.

---

### 4. Exact Associative Segment-Transition Monoid & Constant-Depth (`d = 2`) Recursion

Deterministic verification is factored into contiguous segments `[start_h ..= end_h]` (`4,096` headers per frozen segment, aligned to Ergo's 128-block EIP-37 epochs, with exact boundary splitting at bootstrap `b` and `f = b + k_0 - 1`).

#### 4.1 Compact Boundary State (`BoundaryState`)
Adjacent segments exchange a compact state (~1.8–3.0 KiB):
- `(profile, height, tip_id, tip_timestamp, tip_difficulty, total_work, v1_work_t1, early_v2_work_t2, u_global)`
- `mmr: MmrFrontier` (`leaf_count` and at most 32 peak digests)
- `legacy_anchors` (last `<= 9` multiples of 1,024 through height `843,776`) and `eip37_anchors` (last `<= 9` multiples of 128), sufficient for every legacy and EIP-37 retarget and Appendix B legacy envelope `B_j`
- `modern_bands` (last `<= 10` constant-difficulty 128-block EIP-37 bands, covering the full `L + k_0 = 960` sliding difficulty window)

#### 4.2 Witness-Assisted Exact secp256k1 Point Validation
Ergo's header serializer requires every `GroupElement` (`pk` on v2+, `pk` and `w` on v1) to be either canonical 33-byte infinity `[0; 33]` or a valid compressed secp256k1 point (`0x02/0x03 || x`). Instead of executing ~270 modular multiplications for modular square-root decompression inside the guest, the prover supplies the 32-byte `y` coordinate as private witness and the guest verifies `x < p`, `y < p`, `(y & 1) == (prefix & 1)`, and `y^2 ≡ x^3 + 7 (mod p)` in **3 modular multiplications** (~90× faster, mathematically identical; cross-verified against `k256` across all 1,827,840 mainnet headers).

#### 4.3 Exact Associative Maturity Monoid (`ScoreMonoid`)
For any contiguous segment `S`, define:
- `u_S = gridceil(max(E_legacy(S), floor(3 D_max(S) / 2)))` (early-zone cap contribution)
- `q_S = gridceil(floor(3 D_max(S) / 2))` (modern-zone cap contribution)
- `W_max_k(S)` for zones `k ∈ {0, 1, 2}` (maximum prefix work of origins in zone `k` inside `S`)
- `A_sampled(S)` and `A_exact(S)` (maximum maturity requirements over origins in `S` using caps through the end of `S`).

Composing contiguous segments `L` and `R` raises `L`'s zone-0/1 requirements by `W_max_k(L) + m_k · u_R`, raises `L`'s zone-2 requirements by `W_max_2(L) + m_2 · q_R`, raises `R`'s zone-0/1 requirements by `W_max_k(R) + m_k · u_L`, and takes componentwise maxima. The resulting composition is an **exact associative monoid** (`merge(merge(S_1, S_2), S_3) == merge(S_1, merge(S_2, S_3))`), bit-for-bit identical to a flat sequential pass from genesis across all 1,827,840 headers.

#### 4.4 Constant-Depth (`d = 2`) Recursive Proof Tree with Compile-Time VK Pinning
Three guest programs form a fixed depth-2 tree without unbounded IVC recursion:
1. **Leaf (`leaf-segment`):** Verifies up to 4,096 contiguous headers via `ergo_nipopow_v2_core::segment::verify_segment` and outputs `SHA-256(bincode(SegmentSummary))`.
2. **Level-1 (`agg-l1`):** Compile-time pins the exact leaf verifying key, recursively verifies up to `F` child leaf STARKs (`F = 32` in ZisK, `F = 64` in OpenVM), checks each child's revealed 32-byte digest against `SHA-256(bincode(child.summary))`, runs `merge_segments`, and outputs `SHA-256(bincode(merged_summary))`.
3. **Level-2 Root (`agg-root`):** Compile-time pins the exact Level-1 verifying key, verifies all Level-1 STARKs covering `[1..=b]`, `[b+1..=f]`, and `[f+1..=n]`, runs `check_bootstrap_eligibility`, asserts `stmt.sampled_eligible == true`, and outputs the 32-byte `SHA-256(bincode(BootstrapStatement))`.

At `F = 64`, depth `d = 2` covers `64^2 × 4,096 = 16,777,216` headers (~64 years of Ergo mainnet) without increasing recursion depth.

---

### 5. Heterogeneous Dual-Proof Structural Architecture (`ZisK v1.4.0-alpha` + `OpenVM v2.1.0`)

Single-prover deployments carry implementation-bug risk in complex zkVM circuits. Ergo NiPoPoW V2 supports **Heterogeneous Dual-Proof certification** (`StructuralBackend::DualZiskV14OpenVmV21`), encoding both independent proofs canonically inside `V2Certificate::structural_proof`:

```text
DualStructuralProof = BE32(len(zisk_proof)) || zisk_proof || BE32(len(openvm_proof)) || openvm_proof
```

Both proofs certify the exact same `SHA-256(bincode(BootstrapStatement))` and are committed **jointly** into the Fiat-Shamir audit transcript before sampling any work coordinates:

- **Proof A — ZisK `v1.4.0-alpha` (`RV64IMA`, `Goldilocks^3`, 256-bit `BLAKE3`, DEEP-ALI + FRI/STIR):**
  - Achieves **strict 128-bit security** under `ethereum/soundcalc` JBR and full **128-bit classical collision resistance** via 256-bit BLAKE3.
  - Uses native `Sha256f`, `Blake2br`, and `Blake3f` precompiles and `no_std` in-guest verification (`zisk-verifier::verify_saved_words`).
  - Final `--minimal` STIR proof is **`251,864 B` (`245.96 KiB`)**, verified on pure CPU in **`2 ms`**.
- **Proof B — OpenVM `v2.1.0` (`RV32IM`, `BabyBear^4`, `Poseidon2`, SWIRL + WHIR):**
  - Provides an independent defense-in-depth witness over a distinct ISA, base/extension field, algebraic hash family, and polynomial commitment scheme, configured with OpenVM `v2.1.0`'s standard `*_with_100_bits_security` parameters (**100-bit proven RBR security**). In `DualZiskV14OpenVmV21`, both proofs must verify simultaneously (combining 128-bit ZisK STIR soundness with 100-bit audited/Lean-verified OpenVM defense-in-depth); standalone `OpenVmSwirlV21` is refused by default in strict 128-bit verification mode unless explicitly opted in.
  - Core RV32IM, memory consistency, and SHA-2 circuits are formally verified in Lean and externally audited by zkSecurity.
  - Final Root proof is **`546,289 B` (`533.5 KiB`)**, with incremental depth-2 renewal (delta L1 + Root) completing in **`23.25 s`** on a single RTX 4090.

The `StructuralBackend` envelope also supports standalone `ZiskStirV14` (`245.96 KiB`, `2 ms` STARK verify) with zero wire-format breaking changes once external ZisK v1.4 audits conclude.

---

### 6. Pre-Audit Work Sampling and Zero-Unauthenticated-Context Continuation

Given canonical `x = bincode(BootstrapStatement)` and complete `pi_s = cert.structural_proof`:

```text
audit_seed = SHA-512("Ergo-NiPoPoW-V2/audit/v2/1\0" || BE64(|x|) || x || BE64(|pi_s|) || pi_s)
```

For each geometric scale `F, 2F, 4F, ..., W_P`, **`982` coordinates** are drawn with 2-attempt rejection sampling, opened against `mmr_root(n)` via `MmrMultiproof`, and checked with full native Autolykos v1/v2 PoW.

For exact-tail comparison after bootstrap height `b`, **every boundary value required by Ergo consensus is certified directly inside `BootstrapStatement`**: `(W_B, A_B, T_1, T_2)`, `bootstrap_id`, `bootstrap_timestamp`, `bootstrap_difficulty`, all **9 EIP-37 DAA anchors** (`bootstrap_eip37_anchors`), and all **modern sliding-window difficulty bands** (`bootstrap_modern_bands`). No unauthenticated peer context is accepted. The client validates every header in `(b, n]` natively (codec, parent link, strict timestamps, EIP-37 DAA, native Autolykos v2 PoW) and verifies:

```text
W_total >= max(A_B, T_1 + 19,879 · q_tail, T_2 + 10,807 · q_tail, W_B + 2,083 · q_tail)
```

together with every new origin maturity guard `i ∈ (b, h + k_0 - 1]`.

---

### 7. Measured Full-Mainnet Benchmarks (All 1,827,840 Real Ergo Headers)

All measurements below were executed end-to-end on the complete canonical Ergo mainnet header history through height **`1,827,840`** (`tip = 20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`, `total_work = 2,746,808,805,241,252,741,120`, `mmr_root = 4337ac66b76b1de9edc0b8770de362b73de02e3955523f00c5ec8797aa323e92`, `407.07 MiB` raw headers).

#### 7.1 Proof A — Full Genesis-to-STIR Proving on ZisK `v1.4.0-alpha` (`2× RTX 5090 32 GiB`)

Two independent single-GPU `(zisk-coordinator + zisk-worker-gpu)` pairs processed all 449 segments, 17 Level-1 recursive nodes, 1 Level-2 Root, and STIR `--minimal` wrap with **0 errors and 0 retries**:

| Stage | Scope | Measured Wall-Clock Time | Proof Size | CPU Verify |
| --- | --- | ---: | ---: | ---: |
| **Leaf proofs (449 / 449)** | `seg-00000..=00443` + `444a/b/c` + `445..446` | **`1,349 s` (`22 min 29 s`)** (`~3.00 s` amortized/leaf) | `412,800 B` / leaf | `2–6 ms` / leaf |
| **Level-1 recursion (17 / 17)** | `fan-in=32`: 14 frozen prefix + tail + bridge + suffix | **`255 s` (`4 min 15 s`)** (`35–36 s` / 32-leaf batch) | `412,800 B` / node | `2–6 ms` / node |
| **Level-2 Root (`agg-root`)** | 17 L1 proofs → `BootstrapStatement` (`b=1,819,644`) | **`19 s`** | `412,800 B` (FRI) | `2 ms` |
| **STIR `--minimal` wrap** | `cargo-zisk remote wrap -c` | **`< 1 s`** | **`251,864 B` (`245.96 KiB`)** | **`2 ms`** |
| **Total Genesis-to-STIR** | **All 1,827,840 mainnet headers** | **`1,623 s` (`27 min 03 s`)** | **`245.96 KiB`** | **`2 ms`** |

#### 7.2 Proof B — OpenVM `v2.1.0` Proving & Incremental Depth-2 Aggregation (`RTX 4090 24 GiB`)

| Stage | Scope | Measured GPU Time | Proof Size | CPU Verify |
| --- | --- | ---: | ---: | ---: |
| **Leaf proofs (449 / 449)** | `~27–38 s`/leaf/GPU (`5× RTX 4090` parallel) | `~30 s` avg / leaf / GPU | `522 KiB` / leaf | `0.74 s` / leaf |
| **Level-1 frozen prefix (7 nodes)** | `l1-prefix-00..=06` (`444` leaves, `1..=1,818,624`) | `286.5 s` (`36–53 s` / 64-leaf batch) | `533.5 KiB` × 7 | `14 ms` / batch |
| **Level-1 delta renewal (3 nodes)** | `l1-prefix-tail` (1) + `l1-bridge` (1) + `l1-suffix` (3) | **`12.02 s`** (`3.65 + 3.74 + 4.59 s`) | `533.5 KiB` × 3 | `14 ms` / batch |
| **Level-2 Root (`agg-root`)** | 10 L1 proofs → `BootstrapStatement` (`b=1,819,644`) | **`11.22 s`** | **`546,289 B` (`533.5 KiB`)** | **`14 ms`** |
| **Incremental L1 + Root renewal** | Reuses 7 frozen L1 batches (**99.50%** of history) | **`23.25 s`** | **`533.5 KiB`** | **`14 ms`** |

Cross-zkVM statement check (`cmp -s`) confirmed exact byte-for-byte identity across all 737 bytes of `BootstrapStatement` between ZisK `v1.4.0-alpha` and OpenVM `v2.1.0`.

#### 7.3 Standalone Zero-CUDA Pure-Rust Cold Light-Client Verification

Measured with `ergo-nipopow-v2-aggregator verify-cert` compiled with `--no-default-features` (`ldd`-verified zero CUDA dependencies), consuming **only** the certificate, the `1.75 MiB` exact tail (`1,819,645..=1,827,840`), and fixed verifying keys—zero GPU, zero witness, zero full-history file:

| Light-Client Metric | Standalone ZisK STIR (`ZiskStirV14`) | Heterogeneous Dual-Proof (`DualZiskV14OpenVmV21`) |
| --- | ---: | ---: |
| Certified bootstrap lag (`b = 1,819,644`) | `8,196` blocks (**`11.49 days`**) | `8,196` blocks (**`11.49 days`**) |
| Latest exact-tail mature query (`h = 1,823,986`) | `3,854` blocks (**`5.39 days`**) | `3,854` blocks (**`5.39 days`**) |
| Root structural proof(s) | **`245.96 KiB`** (`251,864 B`) | **`245.96 KiB`** + **`533.5 KiB`** |
| Complete `V2Certificate` size | **`5.54 MiB`** (`5,807,451 B`) | **`6.04 MiB`** (`6,335,262 B`) |
| Exact modern tail (`8,196` headers) | **`1.75 MiB`** (`1,835,904 B`) | **`1.75 MiB`** (`1,835,904 B`) |
| **Total cold sync download** | **`7.29 MiB`** (**`1.79%`** of 407.07 MiB) | **`7.79 MiB`** (**`1.91%`** of 407.07 MiB) |
| **Root STARK verification (CPU-only)** | **`0.002 s` (`2 ms`)** | **`0.224 s`** (both STARKs) |
| **128-bit PoW audit (`13,748` draws)** | **`2.041 s`** | **`2.029 s`** |
| **Exact modern tail (`8,196` headers + PoW)** | **`1.243 s`** | **`1.233 s`** |
| **Total cold client CPU time** | **`3.359 s`** (`3.389 s` `.gz` light CLI) | **`3.535 s`** |
| **Total cold sync download (gzip-9 `.gz`)** | **`5.99 MiB`** (**`1.47%`** of 407.07 MiB) | **`6.23 MiB`** (**`1.53%`** of 407.07 MiB) |
| **Live V8 WebAssembly cold verify (`wasm/verify_v8.mjs`)** | **`4.574 s`** (`< 1 MiB` `.wasm.gz`, zero JS imports) | — |
| Isolated negative tamper checks | **PASS (fail-closed)** | **PASS on BOTH proofs (fail-closed)** |

#### 7.4 Executable V8 WASM Verifier, Live Post-STARK `1,827,976` `ADProofs`, Multi-Peer Fork Selection, CPU Renewal & 100% Reproducible VKs (`v0.4.0`)

To eliminate any prover-liveness dependency for returning light clients, execute real WebAssembly inside V8, prove live post-STARK UTXO state transitions after a difficulty retarget, handle untrusted competing peers, and guarantee bit-for-bit build reproducibility across all pinned verifying keys:

1. **Executable `wasm32-unknown-unknown` `cdylib` Executed Live Inside V8 (`crates/ergo-nipopow-v2-light/src/wasm.rs`, `wasm/verify_v8.mjs`):**
   - Pure-Rust verifier binary (`ergo_nipopow_v2_light.wasm`, **`< 1 MiB` gzip-9** with zero JS imports, zero OpenVM SDK, zero CUDA, zero C++), executed live inside Node.js V8 in CI:
     - Cold 128-bit verification of all `1,827,840` blocks (`.gz` ZisK STIR + `.gz` tail): **`4.574 s`** (`inst = 28.5 ms`).
     - Returning-user `extend-tail` (`+136` live headers `1,827,841..=1,827,976`, zero STARK, crosses EIP-37 retarget): **`28.4 ms`**.
     - Live post-STARK block **`1,827,976`** `ADProofs` (`2,828 B`) + Scorex Tx Merkle verification inside V8: **`27.6 ms`**.
     - Isolated 1-bit PoW tamper rejected fail-closed inside V8 (`Pow(Target)`).
   - Transparent pure-Rust gzip transport reduces cold sync wire size to **`5.99 MiB`** (ZisK STIR `.gz` + tail `.gz`) or **`6.23 MiB`** (Dual `.gz` + tail `.gz`). Note: `ergo-nipopow-v2-light` verifies the ZisK STIR proof natively and reports whether an OpenVM dual proof is attached; full verification of both STARKs uses `ergo-nipopow-v2-aggregator --no-default-features`.
2. **Zero Prover Liveness Cliff (`LightCheckpoint` + `extend-tail`) & Live Post-STARK Block `1,827,976` `ADProofs` (`verify-live-state-proof`):**
   - After one cold verification, the client persists a **`5.6 KiB`** JSON `LightCheckpoint` storing the authenticated tip, EIP-37 anchor ring, and maturity state, and extends it indefinitely with plain Ergo headers only (`~160 KiB/day` at 720 blocks/day, zero STARK download, zero prover server).
   - Verified end-to-end on **136 live Ergo mainnet blocks mined after `1,827,840`** (`1,827,841..=1,827,976`, `30,464 B` wire, crossing the real mainnet EIP-37 difficulty retarget `105028762 -> 105229481` at height `1,827,969`), advancing the certified `state_root` to `25b40830db79b785281b2e76d9d932f97594893d420b24d7336eb7c867ef954819`, and replaying the real **`2,828 B` `ADProofs`** AVL+ batch transition (`59209366...1619 -> 25b40830...4819`, 1 spent input + 2 canonically serialized created boxes verified via `BLAKE2b-256`) and Scorex Tx Merkle proof on live block `1,827,976` in **`0.05 ms`** state verify (`0.030 s` total including 136-header extension, `3/3` isolated tamper checks rejected).
3. **End-to-End Trustless Mainnet AVL+ `ADProofs` (`1,823,986`) & Transaction Merkle (`1,823,985`, `verify-state-proof`):**
   - Extracts certified headers `h - 1 = 1,823,985` and `h = 1,823,986` directly from the verified `.gz` Dual certificate and exact tail, then replays the real **`2,809 B` `ADProofs`** AVL+ state transition (`88aaa010...f619 -> 46945bcd...9d819`) and 5-level Scorex transaction Merkle inclusion proof in **`0.06 ms`** (`3/3` isolated tamper checks rejected).
4. **Untrusted Multi-Peer Fork Selection (`compare-certs`, `compare_peer_certificates`):**
   - Evaluates competing `(V2Certificate, exact_tail)` pairs from multiple untrusted peers, rejects invalid/tampered peers fail-closed, and deterministically selects the heaviest valid chain (`select_best`). Verified in CI against a 1-bit tampered malicious peer alongside honest Dual and STIR mirrors.
5. **Measured Permissionless CPU-Only Proving (Zero GPU, `scripts/renew_zisk_cpu.sh`):**
   - Reusing the published `6.58 MiB` `zisk-l1-1827840-prod128-archive.tar.gz` (14 immutable L1 proofs covering `99.5%` of history), a real shifting mainnet leaf segment (`seg-00444b`, 63 headers, `expected_sha256 = 87e93842...587c`) was proved and verified on a 16-core x86_64 CPU with zero GPU via `cargo-zisk-cpu prove -m -y`: **`608.97 s` (`10 min 09 s`)** prove time (`652.65 s` wall clock including Proofman init), **`43.12 GiB` peak RSS**, `0` swaps, `Proof verified successfully`.
6. **100% Path-Independent Reproducible Verifying Keys (`scripts/verify_reproducible_vks.sh`, `docker/reproducible-zisk-vks.Dockerfile`):**
   - All 6 guest `Cargo.lock` files (`guests-zisk/*` and `guests/*`) are committed in-tree, and **all 6 compiled ELFs across both ZisK `v1.4.0-alpha` and OpenVM `v2.1.0`** in the live `v0.4.0` mainnet Dual-Proof snapshot are built with deterministic `--remap-path-prefix` flags (zero build-host paths in any ELF).
   - `scripts/verify_reproducible_vks.sh` stages into a canonical path (`/tmp/ergo-nipopow-v2-repro`) so Cargo's path-dependency metadata hashes and LLVM LTO symbol layout are 100% identical regardless of clone path, reproducing **all 3 live `v0.4.0` ZisK ROM roots** (`leaf-segment`, `agg-l1`, `agg-root`) and the **OpenVM `v2.1.0` `leaf-segment` `.vmexe` SHA-256** (`e9a785b199d26dbc99fa949291474aaea4cffe72b34592714e7ce26418f3de8e`) **bit-for-bit**.

#### 7.5 Verified Mainnet Commitments, Pinned VKs & Artifact SHA-256 Digests (`v0.4.0`)

- **Certified tip (`n = 1,827,840`):** `20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`
- **Certified bootstrap (`b = 1,819,644`):** `6e97a4d1f03d81766c2c0b59cf4fadf19a961ee6fe37cfb08f7000eefb61f2e2`
- **Verified mature exact-tail header (`h = 1,823,986`):** `f6da2c12147269555ae8f89cdc22833609eefb7f48bd87a717d62f8466d05cf6`
- **Bagged SHA-256 MMR root:** `4337ac66b76b1de9edc0b8770de362b73de02e3955523f00c5ec8797aa323e92`
- **Identical Root STARK public value (`SHA-256(bincode(BootstrapStatement))`):** `e7981fbc64af4abdd38292792584f1d9850ee6fb293f12c27f2dead07a55edbc`
- **Pinned ZisK `v1.4.0-alpha` path-independent ROM roots (`program_vk`, reproduced bit-for-bit via `scripts/verify_reproducible_vks.sh`):**
  - `leaf-segment`: `[6729894743773666772, 11352437898911962852, 7890323190423858886, 1129626941119155303]` (`HashID: 72a928ea28a2af5d6e4d0d3a690e328760df7ae5cec677aa3e3af1cbb833cbfd`)
  - `agg-l1`: `[13152692753993774254, 9128719786947234642, 6922258063440026975, 14663576450590590947]` (`HashID: e28276865c69891f0dcdb5540291c3c66ad8eee67b1112bb96e8519baa6e9cdd`)
  - `agg-root`: `[11772000642296811191, 2917608110684279903, 7269122849900466967, 12697094355253129467]` (`HashID: 06b25c2f911bc94def7bef115897f4e17f2773e738ab6e925b53ea0ad8a5ff19`)
- **Pinned OpenVM `v2.1.0` path-independent program commits (zero host paths across all 3 guest ELFs):**
  - `leaf-segment`: `exe = 209f093a91912f2582f13d0ec312994cad923a3eb072c2556e0b0540066a756c`, `vm = be60085138e24e74d34bbf70688cfd227a710051eba715206e9de61d8f3da95d` (`.vmexe` SHA-256 `e9a785b199d26dbc99fa949291474aaea4cffe72b34592714e7ce26418f3de8e`)
  - `agg-l1`: `exe = e1876561eabd7f17d08cfe6db009b046fbd8df4eeb98a83cd2459b0be4369e47`, `vm = 18edab2b9e1c9c2a96e5de06283fbc40106f57426cee5e21d3b93721726deb45`
- **Release `v0.4.0` artifacts (`SHA256SUMS.txt`):**
  - `ergo-mainnet-1827840-prod128-dual.npv2.bin` (`6,335,262 B`): `ed4f741ef4bf94c11bfed61d4f26500e60ef9b7d522fd77541009b660cd36356`
  - `ergo-mainnet-1827840-prod128-dual.npv2.bin.gz` (`5,176,961 B`): `0455f0be8e3d0526a9b0b5f4c86e6f8a824dc4e0934036d0b683b88de7801ba2`
  - `ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin` (`5,807,451 B`): `562cfa2100c6a1d74f09c669021d0d01bc2a6cdb2b4d3a34e2b042c0467c3767`
  - `ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin.gz` (`4,918,630 B`): `22aa9e474bda16c32acdd8a0d5cde0c273d85892af078f01f63a88f047ecca2b`
  - `tail-1819645-1827840.u32le` (`1,835,904 B`): `b0eb7b08b8b8d281b4cc2382f39da51f78d316c62cd048d52af4d795cadb76f3`
  - `tail-1819645-1827840.u32le.gz` (`1,360,716 B`): `753ed8a27a9e4dfbcd262e2eb8c0f75b453e704fb745f31e2dbdeaed9edd40e2`
  - `root-agg.vk` (`95,973 B`): `15d415ec0e8dc7910c771c0fc699b0ebec5a42512c595a8f5e9dcd962e6c1d2b`
  - `root-baseline.json` (`1,263 B`): `4e1441e68c98cf3c99aaf5095ed79f5a1e4bd0ac88c785b6ad51e6a7e0a77d58`
  - `zisk-root-1827840-prod128-result.tar.gz` (`655,781 B`): `d4ff11eb1ed426f20569b1ee17cae27498bf78d88ecd2363e833f735c816a878`
  - `zisk-l1-1827840-prod128-archive.tar.gz` (`6,900,514 B`, 17 L1 proofs): `9d938e4ccee202bba45a21c9295be96df842d1d87a3c1c31ce20d74e09b0c218`

---

### 8. Adversarial Testing & Ecosystem Adoption Roadmap

#### Fail-Closed Negative Test Coverage
1. **Core consensus & exact-tail tip-binding negative suite (`crates/ergo-nipopow-v2-core/tests/adversarial_negatives.rs`, `tail_binds_statement.rs`, PASS):** Rejects mutated genesis, broken parent link, non-increasing timestamps, altered difficulty, off-curve/wrong-parity secp256k1 witness, trailing header bytes, non-contiguous segment merges, PoW-era mismatches, tampered `pi_s` audit binding, corrupted MMR siblings, tampered Autolykos PoW nonces, cross-profile substitution, malformed `DualStructuralProof` framing, and exact-tail / `BootstrapStatement` tip mismatches (`tip_id`, `total_work`, `tip_height`, truncated tail).
2. **Standalone light-client, live V8 WASM, state-proof & multi-peer negative suite (`crates/ergo-nipopow-v2-light`, `wasm/verify_v8.mjs`, PASS):** Rejects isolated 1-bit tampers on real mainnet `1,823,986` and live post-STARK `1,827,976` `ADProofs` bytes, created box bytes, expected `state_root`, Scorex transaction Merkle leaves, post-`1,827,840` `extend-tail` headers (both natively and inside V8 WebAssembly), and malicious peer certificates in `compare-certs`.
3. **Live mainnet certificate tamper suite (`ergo-nipopow-v2-aggregator verify-cert`, PASS on both `DualZiskV14OpenVmV21` and `ZiskStirV14`):** Rejects isolated single-fault mutations on (1) `BootstrapStatement.total_work + 1`, (2) 1-bit flip in `structural_proof` audit binding, (3) 1-bit flip in `audit.multiproof.siblings[0]`, (4) 1-bit flip in tail header PoW nonce, (5) direct 1-bit tamper on the ZisK STIR proof and field tamper on OpenVM `user_pvs_proof`, and (6) tampered `bootstrap_eip37_anchors` (including 1 ms timestamp perturbation).

#### Remaining Ecosystem Integration Gates
Before production deployment inside end-user wallets securing mainnet funds:
1. **Independent external security audit** of `ergo-nipopow-v2-core`, `ergo-nipopow-v2-light`, the pinned ZisK and OpenVM guest binaries, and the constant-depth (`d = 2`) extraction argument, alongside completion of ZisK `v1.4`'s ongoing external audits.
2. **Ergo node transport integration:** Serving verified `(V2Certificate, exact_tail)` bundles via Ergo node REST/P2P endpoints and integrating `ergo_nipopow_v2_light.wasm` directly into Ergo browser/mobile light wallets.
