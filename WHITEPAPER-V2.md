# Ergo NiPoPoW V2
## Strict 128-Bit Incremental Post-Quantum Certification of Ergo Header History

**A. Shannon** · 26 November 2026 · Version 0.2.0

---

### Abstract

An Ergo light client presented with competing header histories must identify a mature header on the valid chain of greatest cumulative proof-of-work. Classical superblock proofs (NiPoPoW V1) compare sparse interlink subchains without executing every hidden contextual difficulty transition between visible superblocks. **Ergo NiPoPoW V2** certifies the complete deterministic Ergo header history from genesis—canonical VLQ serialization, `BLAKE2b-256` header identifiers, parent links, strictly increasing timestamps, height-bound Autolykos era selectors, canonical secp256k1 point membership, all-era contextual difficulty adjustment (initial era, Autolykos v2 activation resets, legacy 1,024-block linear regression, and EIP-37 128-block clamped averages), cumulative work intervals, and maturity eligibility guards—while verifying native Autolykos proof-of-work at work-weighted geometric audit coordinates and across a short exact recent tail.

Any untrusted peer can generate and renew certificates from existing mainnet headers with **zero hard fork, zero soft fork, zero miner change, zero trusted setup, and zero elliptic-curve pairing assumptions**.

Five architectural properties make full-history 128-bit verification practical on commodity hardware:

1. **Strict 128-bit end-to-end parameter certification (`V2Production128`):** Every analytical error term (Autolykos v2 rank bound, early-tag survival, geometric audit miss at `Q_A = 2^128 + 1`, global race, and local race) is machine-certified `<= 2^-130` in pure exact rational arithmetic (`scripts/certify_profiles.py`, zero floating point), with total analytical union sum **`<= 2^-128.35 < 2^-128`**.
2. **Append-only SHA-256 Work-Interval MMR:** Leaf preimages commit only to `(profile32, height, W(i-1), W(i), raw_header)` and never hash the snapshot height `n`. Appending blocks invalidates zero prior leaves, internal nodes, or segment proofs, and removes fixed-depth height ceilings (`n < 2^31`, ~8,000 years of Ergo blocks). Canonical deduplicated multiproofs reduce audit sibling digests by ~75%.
3. **Exact associative segment-transition monoid & constant-depth (`d = 2`) recursion:** The entire deterministic Ergo consensus header relation and all three maturity zones decompose into an exact associative monoid over contiguous 4,096-header segments. Segments prove in parallel and fold at constant depth `d = 2` (capacity `64^2 × 4,096 = 16,777,216` headers, ~64 years) with compile-time child-program VK pinning at every level.
4. **Heterogeneous Dual-Proof structural certification (`ZisK v1.4.0-alpha` STIR + `OpenVM v2.1.0` SWIRL/WHIR):** The exact byte-identical `BootstrapStatement` is proved simultaneously by two completely independent transparent post-quantum zkVMs over distinct ISAs, finite fields, hash functions, and polynomial commitment schemes, jointly bound before deriving the Fiat-Shamir work audit.
5. **Zero unauthenticated light-client context:** `BootstrapStatement` embeds the STARK-certified bootstrap timestamp, difficulty, all 9 EIP-37 DAA anchors, and all modern sliding-window difficulty bands at bootstrap height `b`. The exact-tail verifier consumes zero unauthenticated side-channel data.

**Measured end-to-end mainnet results across all 1,827,840 canonical Ergo mainnet headers** (tip `20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`, 407.07 MiB raw headers):
- **Proof A (`ZisK v1.4.0-alpha`, `RV64IMA`, `Goldilocks^3`, 256-bit `BLAKE3`, STIR `--minimal`, 128-bit `ethereum/soundcalc` JBR):** All 449 leaves (`1,460 s`) + 17 Level-1 recursive proofs (`347 s`) + 1 Level-2 Root (`23 s`) + STIR wrap (`< 1 s`) = **`30 min 30 s`** total on `2× RTX 5090`, producing one **`243.27 KiB` (`249,112 B`)** root proof verified on pure CPU in **`2 ms`**.
- **Proof B (`OpenVM v2.1.0`, `RV32IM`, `BabyBear^4`, `Poseidon2`, SWIRL/WHIR, zkSecurity audited & Lean-verified):** All 449 leaves + 10 Level-1 proofs (`320.8 s`) + 1 Level-2 Root (`12.10 s`), producing one **`533.5 KiB` (`546,306 B`)** proof over the **exact byte-identical `BootstrapStatement`** (`SHA-256 = e7981fbc64af4abdd38292792584f1d9850ee6fb293f12c27f2dead07a55edbc`), with **`27.44 s`** incremental L1+Root renewal reusing 99.5% of frozen history.
- **Cold witness-free CPU light-client verification (zero CUDA, zero full history):**
  - **Dual-Proof (`6.05 MiB` cert + `1.75 MiB` exact tail = `7.80 MiB`, `1.92%` of raw headers):** **`3.508 s`** total (`0.195 s` both STARKs + `2.035 s` 13,748-draw audit + `1.229 s` 8,196-header exact tail certifying mature height **`h = 1,823,986`**).
  - **Standalone ZisK STIR (`5.52 MiB` cert + `1.75 MiB` exact tail = `7.27 MiB`, `1.79%`):** **`3.462 s`** total (**`0.002 s`** STIR STARK + `2.142 s` audit + `1.266 s` exact tail).
  - **Fail-closed tamper resistance:** All isolated single-fault tamper tests across both proofs, statement fields, MMR siblings, tail PoW, and EIP-37 anchors are rejected (`NEGATIVE_TAMPER_SUITE_PASS`).

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
  - Final `--minimal` STIR proof is **`249,112 B` (`243.27 KiB`)**, verified on pure CPU in **`2 ms`**.
- **Proof B — OpenVM `v2.1.0` (`RV32IM`, `BabyBear^4`, `Poseidon2`, SWIRL + WHIR):**
  - Provides an independent defense-in-depth witness over a distinct ISA, base/extension field, algebraic hash family, and polynomial commitment scheme.
  - Core RV32IM, memory consistency, and SHA-2 circuits are formally verified in Lean and externally audited by zkSecurity.
  - Final Root proof is **`546,306 B` (`533.5 KiB`)**, with incremental depth-2 renewal (delta L1 + Root) completing in **`27.44 s`** on a single RTX 4090.

The `StructuralBackend` envelope also supports standalone `ZiskStirV14` (`243.27 KiB`, `2 ms` STARK verify) with zero wire-format breaking changes once external ZisK v1.4 audits conclude.

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
| **Leaf proofs (449 / 449)** | `seg-00000..=00443` + `444a/b/c` + `445..446` | **`1,460 s` (`24 min 20 s`)** (`~3.06 s` amortized/leaf) | `412,800 B` / leaf | `2–6 ms` / leaf |
| **Level-1 recursion (17 / 17)** | `fan-in=32`: 14 frozen prefix + tail + bridge + suffix | **`347 s` (`5 min 47 s`)** (`46–51 s` / 32-leaf batch) | `412,800 B` / node | `2–6 ms` / node |
| **Level-2 Root (`agg-root`)** | 17 L1 proofs → `BootstrapStatement` (`b=1,819,644`) | **`23 s`** | `412,800 B` (FRI) | `2 ms` |
| **STIR `--minimal` wrap** | `cargo-zisk remote wrap -c` | **`< 1 s`** | **`249,112 B` (`243.27 KiB`)** | **`2 ms`** |
| **Total Genesis-to-STIR** | **All 1,827,840 mainnet headers** | **`1,830 s` (`30 min 30 s`)** | **`243.27 KiB`** | **`2 ms`** |

#### 7.2 Proof B — OpenVM `v2.1.0` Proving & Incremental Depth-2 Aggregation (`RTX 4090 24 GiB`)

| Stage | Scope | Measured GPU Time | Proof Size | CPU Verify |
| --- | --- | ---: | ---: | ---: |
| **Leaf proofs (449 / 449)** | `~30–41 s`/leaf/GPU (`5× RTX 4090` parallel) | `~31 s` avg / leaf / GPU | `522–616 KiB` / leaf | `0.24 s` / leaf |
| **Level-1 frozen prefix (7 nodes)** | `l1-prefix-00..=06` (`444` leaves, `1..=1,818,624`) | `305.4 s` (`39–48 s` / 64-leaf batch) | `533.5 KiB` × 7 | `14 ms` / batch |
| **Level-1 delta renewal (3 nodes)** | `l1-prefix-tail` (1) + `l1-bridge` (1) + `l1-suffix` (3) | **`15.34 s`** (`4.44 + 4.70 + 6.15 s`) | `533.5 KiB` × 3 | `14 ms` / batch |
| **Level-2 Root (`agg-root`)** | 10 L1 proofs → `BootstrapStatement` (`b=1,819,644`) | **`12.10 s`** | **`546,306 B` (`533.5 KiB`)** | **`14 ms`** |
| **Incremental L1 + Root renewal** | Reuses 7 frozen L1 batches (**99.50%** of history) | **`27.44 s`** | **`533.5 KiB`** | **`14 ms`** |

Cross-zkVM statement check (`cmp -s`) confirmed exact byte-for-byte identity across all 737 bytes of `BootstrapStatement` between ZisK `v1.4.0-alpha` and OpenVM `v2.1.0`.

#### 7.3 Standalone Zero-CUDA Pure-Rust Cold Light-Client Verification

Measured with `ergo-nipopow-v2-aggregator verify-cert` compiled with `--no-default-features` (`ldd`-verified zero CUDA dependencies), consuming **only** the certificate, the `1.75 MiB` exact tail (`1,819,645..=1,827,840`), and fixed verifying keys—zero GPU, zero witness, zero full-history file:

| Light-Client Metric | Standalone ZisK STIR (`ZiskStirV14`) | Heterogeneous Dual-Proof (`DualZiskV14OpenVmV21`) |
| --- | ---: | ---: |
| Certified bootstrap lag (`b = 1,819,644`) | `8,196` blocks (**`11.49 days`**) | `8,196` blocks (**`11.49 days`**) |
| Latest exact-tail mature query (`h = 1,823,986`) | `3,854` blocks (**`5.39 days`**) | `3,854` blocks (**`5.39 days`**) |
| Root structural proof(s) | **`243.27 KiB`** (`249,112 B`) | **`243.27 KiB`** + **`533.5 KiB`** |
| Complete `V2Certificate` size | **`5.52 MiB`** (`5,792,092 B`) | **`6.05 MiB`** (`6,344,950 B`) |
| Exact modern tail (`8,196` headers) | **`1.75 MiB`** (`1,835,904 B`) | **`1.75 MiB`** (`1,835,904 B`) |
| **Total cold sync download** | **`7.27 MiB`** (**`1.79%`** of 407.07 MiB) | **`7.80 MiB`** (**`1.92%`** of 407.07 MiB) |
| **Root STARK verification (CPU-only)** | **`0.002 s` (`2 ms`)** | **`0.195 s`** (both STARKs) |
| **128-bit PoW audit (`13,748` draws)** | **`2.142 s`** | **`2.035 s`** |
| **Exact modern tail (`8,196` headers + PoW)** | **`1.266 s`** | **`1.229 s`** |
| **Total cold client CPU time** | **`3.462 s`** (`3.274 s` on v0.3.0) | **`3.508 s`** (`3.481 s` on v0.3.0) |
| **Total cold sync download (gzip-9 `.gz`)** | **`5.97 MiB`** (**`1.47%`** of 407.07 MiB) | **`6.24 MiB`** (**`1.53%`** of 407.07 MiB) |
| Isolated negative tamper checks | **PASS (fail-closed)** | **PASS on BOTH proofs (fail-closed)** |

#### 7.4 Standalone WASM Light Verifier, Indefinite Plain-Header Continuation, Real Mainnet AVL+ State Proofs & CPU-Only Proving (`v0.3.0`)

To eliminate any prover-liveness dependency for returning light clients, connect certified headers directly to Ergo's UTXO state layer, and empirically measure GPU-free proving:

1. **Zero-Prover-SDK Light Verifier & `wasm32-unknown-unknown` Target (`crates/ergo-nipopow-v2-light`):**
   - Compiles cleanly to native CPU and **`wasm32-unknown-unknown`** with zero OpenVM SDK, zero CUDA, and zero C++ dependencies (`zisk-verifier v1.4.0-alpha`, `ergo_avltree_rust v0.1.1`, `k256`, pure-Rust `flate2`).
   - Supports transparent pure-Rust gzip transport, reducing cold sync wire size to **`5.97 MiB`** (ZisK STIR `.gz` + tail `.gz`) or **`6.24 MiB`** (Dual `.gz` + tail `.gz`). Note: `ergo-nipopow-v2-light` verifies the ZisK STIR proof natively and reports whether an OpenVM dual proof is attached; full verification of both STARKs uses `ergo-nipopow-v2-aggregator --no-default-features`.
2. **Zero Prover Liveness Cliff (`LightCheckpoint` + `extend-tail`):**
   - After one cold verification, the client persists a **`5,748 B` (`5.6 KiB`)** JSON `LightCheckpoint` storing the authenticated tip, EIP-37 anchor ring, and maturity state.
   - Returning clients extend this checkpoint indefinitely with plain Ergo headers only (`~160 KiB/day` at 720 blocks/day, zero STARK download, zero prover server).
   - Verified end-to-end on **136 live Ergo mainnet blocks mined after `1,827,840`** (`1,827,841..=1,827,976`, `30,464 B` wire, crossing the real mainnet EIP-37 difficulty retarget `105028762 -> 105229481` at height `1,827,969`) in **`0.147 s`**, advancing the certified `state_root` to `25b40830db79b785281b2e76d9d932f97594893d420b24d7336eb7c867ef954819`. Isolated 1-bit tampers on parent link, EIP-37 `nBits` at `1,827,969`, and Autolykos v2 PoW nonce at `1,827,976` all fail closed.
3. **End-to-End Trustless Mainnet AVL+ `ADProofs` & Transaction Merkle Verification (`verify-state-proof`):**
   - Extracts certified headers `h - 1 = 1,823,985` and `h = 1,823,986` directly from the verified `.gz` certificate and exact tail, then replays:
     - The real Ergo mainnet **`2,809 B` `ADProofs`** AVL+ batch state transition via `ergo_avltree_rust::BatchAVLVerifier` (`BLAKE2b-256(adProofs) == adProofsRoot`, removing the spent box `e9930f6b...0148` and inserting both canonically serialized created boxes verified via `BLAKE2b-256(raw) == boxId`), matching `header(1,823,986).state_root` (`46945bcd...9d819`) bit-for-bit from `header(1,823,985).state_root` (`88aaa010...f619`).
     - The real Ergo mainnet 5-level Scorex Merkle membership proof (`BLAKE2b-256` with `0x00`/`0x01` domain tags) for block `1,823,985` (12 transactions) against `header(1,823,985).transactions_root`.
   - Combined state + transaction proof verification time: **`0.09 ms`**, with **`3/3` isolated tamper checks** (mutated `ADProofs` byte, mutated created-box byte, mutated expected `state_root`, plus mutated Merkle leaf) rejected fail-closed.
4. **Measured Permissionless CPU-Only Proving (Zero GPU, `scripts/renew_zisk_cpu.sh`):**
   - Reusing the published `6.57 MiB` `zisk-l1-1827840-prod128-archive.tar.gz` (14 immutable L1 proofs covering `99.5%` of history), a real shifting mainnet leaf segment (`seg-00444b`, 63 headers, `expected_sha256 = 87e93842...587c`) was proved and verified on a 16-core x86_64 CPU with zero GPU via `cargo-zisk-cpu prove -m -y`: **`608.97 s` (`10 min 09 s`)** prove time (`652.65 s` wall clock including Proofman init), **`43.12 GiB` peak RSS**, `0` swaps, `Proof verified successfully`.
   - This establishes empirically both that GPU-free permissionless renewal works on a standard 64 GiB RAM CPU host and its exact computational trade-off relative to single-GPU renewal (`~30 s`).
5. **Reproducible Verifying Keys (`scripts/verify_reproducible_vks.sh` & Committed Guest `Cargo.lock`s):**
   - All 6 guest `Cargo.lock` files (`guests-zisk/*` and `guests/*`) are committed in-tree.
   - Compiling ZisK guests with `--remap-path-prefix` strips 100% of host paths and was empirically verified across two distinct directory trees to produce bit-for-bit identical ZisK ROM roots. (Note: the initial `v0.2.0` `1,827,840` proof snapshot predated `--remap-path-prefix`, so `agg-l1` reproduces its `v0.2.0` ROM root bit-for-bit across directories while `leaf-segment` and `agg-root` require the `--remap-path-prefix` build for path-independent reproduction in subsequent proving campaigns.)

#### 7.5 Verified Mainnet Commitments, Pinned VKs & Artifact SHA-256 Digests

- **Certified tip (`n = 1,827,840`):** `20ed709e5e9ba0d40fa941b2de53a3cdbd5bf29950b4a40adad8d244209ff9b3`
- **Certified bootstrap (`b = 1,819,644`):** `6e97a4d1f03d81766c2c0b59cf4fadf19a961ee6fe37cfb08f7000eefb61f2e2`
- **Verified mature exact-tail header (`h = 1,823,986`):** `f6da2c12147269555ae8f89cdc22833609eefb7f48bd87a717d62f8466d05cf6`
- **Bagged SHA-256 MMR root:** `4337ac66b76b1de9edc0b8770de362b73de02e3955523f00c5ec8797aa323e92`
- **Identical Root STARK public value (`SHA-256(bincode(BootstrapStatement))`):** `e7981fbc64af4abdd38292792584f1d9850ee6fb293f12c27f2dead07a55edbc`
- **Pinned ZisK `v1.4.0-alpha` ROM roots (`program_vk`):**
  - `leaf-segment`: `[9110326089375293727, 2656454419186733083, 1581716303455200999, 11820023294815474883]`
  - `agg-l1`: `[5319951898812481023, 12834882460020413992, 8904808812702811473, 9762453858803393301]`
  - `agg-root`: `[2061927828237341284, 1907988207398174607, 15624447174404746195, 12050011039068599532]`
- **Pinned OpenVM `v2.1.0` program commits:**
  - `leaf-segment`: `exe = 1d60421eadd0d43144c4f7544a1d1756e9bdf040f7e1c14b2476464e985eda0f`, `vm = be60085138e24e74d34bbf70688cfd227a710051eba715206e9de61d8f3da95d`
  - `agg-l1`: `exe = 1813f5139e74df50a695da1c12d92f4920f75e734f6baf0721cb0f1c952a2472`, `vm = 18edab2b9e1c9c2a96e5de06283fbc40106f57426cee5e21d3b93721726deb45`
- **Release `v0.2.0` artifacts:**
  - `ergo-mainnet-1827840-prod128-dual.npv2.bin` (`6,344,950 B`): `49a561f55a8a7624f3f4a5d57ea32cdba6e0f37b78c65e9777bf587ab7afc845`
  - `ergo-mainnet-1827840-prod128-zisk-stir.npv2.bin` (`5,792,092 B`): `ca047af2db8fb68747f6e6e3745bb2dd21c9d6dc183126b4e975e81b258e5af1`
  - `tail-1819645-1827840.u32le` (`1,835,904 B`): `b0eb7b08b8b8d281b4cc2382f39da51f78d316c62cd048d52af4d795cadb76f3`
  - `zisk-root-1827840-prod128-result.tar.gz` (`653,471 B`): `a028cab74ee2fad1a9956fe368d301122de07de059f1a8060dca8b5ef286c55d`
  - `zisk-l1-1827840-prod128-archive.tar.gz` (`6,887,517 B`, 17 L1 proofs): `06ba502525456f801759c812faa8516682725176c8c3f9801d5ff090f0eee10d`

---

### 8. Adversarial Testing & Ecosystem Adoption Roadmap

#### Fail-Closed Negative Test Coverage
1. **Core consensus negative suite (`crates/ergo-nipopow-v2-core/tests/adversarial_negatives.rs`, PASS):** Rejects mutated genesis, broken parent link, non-increasing timestamps, altered difficulty, off-curve/wrong-parity secp256k1 witness, trailing header bytes, non-contiguous segment merges, PoW-era mismatches, tampered `pi_s` audit binding, corrupted MMR siblings, tampered Autolykos PoW nonces, cross-profile substitution, and malformed `DualStructuralProof` framing.
2. **Standalone light-client, state-proof & tail-extension negative suite (`crates/ergo-nipopow-v2-light`, PASS):** Rejects isolated 1-bit tampers on real mainnet `1,823,986` `ADProofs` bytes, created box bytes, expected `state_root`, `1,823,985` Scorex transaction Merkle leaf, and real post-`1,827,840` `extend-tail` headers (parent link, EIP-37 retarget `nBits` at `1,827,969`, and Autolykos v2 PoW nonce at `1,827,976`).
3. **Live mainnet certificate tamper suite (`ergo-nipopow-v2-aggregator verify-cert`, PASS on both `DualZiskV14OpenVmV21` and `ZiskStirV14`):** Rejects isolated single-fault mutations on (1) `BootstrapStatement.total_work + 1`, (2) 1-bit flip in `structural_proof` audit binding, (3) 1-bit flip in `audit.multiproof.siblings[0]`, (4) 1-bit flip in tail header PoW nonce, (5) direct 1-bit tamper on the ZisK STIR proof and field tamper on OpenVM `user_pvs_proof`, and (6) tampered `bootstrap_eip37_anchors` (including 1 ms timestamp perturbation).

#### Remaining Ecosystem Integration Gates
Before production deployment inside end-user wallets securing mainnet funds:
1. **Independent external security audit** of `ergo-nipopow-v2-core`, `ergo-nipopow-v2-light`, the pinned ZisK and OpenVM guest binaries, and the constant-depth (`d = 2`) extraction argument, alongside completion of ZisK `v1.4`'s ongoing external audits.
2. **Path-remapped proving campaign & Ergo node transport:** Producing the next mainnet snapshot under `--remap-path-prefix` (`scripts/verify_reproducible_vks.sh`) for universal path-independent ELF/VK verification across all three guest stages, and serving verified `(V2Certificate, exact_tail)` bundles via Ergo node REST/P2P endpoints.
