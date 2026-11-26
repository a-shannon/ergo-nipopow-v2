//! Incremental segment-transition verifier and constant-depth (`d = 2`) associative
//! segment merger.
//!
//! This exact pure-Rust code runs identically:
//! - natively on the host (for fast zero-mismatch full-chain verification & witness prep), and
//! - inside the OpenVM v2.1.0 transparent post-quantum STARK guests (`guest-leaf` and `guest-agg`).

use alloc::vec::Vec;

use crate::daa::{
    appendix_b_legacy_bound, decode_compact, required_difficulty, DaaAnchor, DaaError,
    EIP37_EPOCH, EIP37_FIRST_CHILD, INITIAL_DIFFICULTY, LEGACY_EPOCH, V2_RESET_DIFFICULTY,
};
use crate::header::{
    blake2b256, Header, HeaderError, HeaderPointWitness, AUTOLYKOS_V1_LAST_HEIGHT,
    MAINNET_GENESIS_ID,
};
use crate::mmr::{hash_leaf, mainnet_profile32, MmrError, MmrFrontier};
use crate::monoid::ScoreMonoid;
use crate::profile::{ProfileId, ProfileParams};

/// Exact boundary state carried across contiguous segments (~1.8 KiB serialized).
/// Contains everything needed for deterministic Ergo DAA, append-only MMR, and
/// exact sliding-window maturity caps with zero missing history.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BoundaryState {
    pub profile: ProfileId,
    /// Height of the last verified header (`0` before genesis).
    pub height: u32,
    pub tip_id: [u8; 32],
    pub tip_timestamp: i64,
    pub tip_difficulty: u128,
    pub total_work: u128,
    /// Non-genesis v1 cumulative work `T1 = W(min(n, 417_791))`.
    pub v1_work_t1: u128,
    /// Cumulative work through end of early-v2 zone `T2 = W(min(n, s_L - 1))`.
    pub early_v2_work_t2: u128,
    /// Append-only SHA-256 Work-Interval MMR frontier.
    pub mmr: MmrFrontier,
    /// Up to 9 most recent legacy epoch boundary anchors (heights divisible by 1024, <= 843_776).
    pub legacy_anchors: Vec<DaaAnchor>,
    /// Up to 9 most recent EIP-37 epoch boundary anchors (heights divisible by 128).
    pub eip37_anchors: Vec<DaaAnchor>,
    /// Recent modern difficulty bands (`(band_start_height, difficulty)`) covering at least
    /// the last `L + k0` blocks (~10 entries max, 160 bytes) for exact `M_P(i)` computation.
    pub modern_bands: Vec<(u32, u128)>,
    /// Running global cap `U_global` across `[1..=height]`.
    pub u_global: u128,
}

impl BoundaryState {
    pub fn initial(profile: ProfileId) -> Self {
        Self {
            profile,
            height: 0,
            tip_id: [0u8; 32],
            tip_timestamp: 0,
            tip_difficulty: 0,
            total_work: 0,
            v1_work_t1: 0,
            early_v2_work_t2: 0,
            mmr: MmrFrontier::empty(),
            legacy_anchors: Vec::new(),
            eip37_anchors: Vec::new(),
            modern_bands: Vec::new(),
            u_global: 0,
        }
    }

    /// Extract the 32-byte bagged MMR root at the current height.
    pub fn mmr_root(&self) -> Result<[u8; 32], MmrError> {
        let p32 = mainnet_profile32();
        self.mmr.root(&p32)
    }

    fn record_anchor(ring: &mut Vec<DaaAnchor>, anchor: DaaAnchor) {
        if ring.len() == 9 {
            ring.remove(0);
        }
        ring.push(anchor);
    }

    fn record_modern_band(&mut self, height: u32, difficulty: u128, window_span: u32) {
        // Singleton at 844_672; thereafter constant on [844_673 + 128*j, 844_800 + 128*j].
        if height < 844_672 {
            return;
        }
        let band_start = if height == 844_672 {
            844_672
        } else {
            let offset = (height - EIP37_FIRST_CHILD) / EIP37_EPOCH;
            EIP37_FIRST_CHILD + offset * EIP37_EPOCH
        };
        if let Some(last) = self.modern_bands.last() {
            if last.0 == band_start {
                debug_assert_eq!(last.1, difficulty);
                return;
            }
        }
        self.modern_bands.push((band_start, difficulty));
        // Prune bands strictly older than `height - window_span - 128`
        let keep_from = height.saturating_sub(window_span + EIP37_EPOCH);
        while self.modern_bands.len() > 2 && self.modern_bands[1].0 <= keep_from {
            self.modern_bands.remove(0);
        }
    }

    /// Maximum difficulty in `[origin - window_span, height]` using `modern_bands`.
    fn modern_window_max(&self, origin: u32, window_span: u32) -> u128 {
        let lower = origin.saturating_sub(window_span);
        let mut best = 0u128;
        for (idx, &(start, diff)) in self.modern_bands.iter().enumerate() {
            let end = self
                .modern_bands
                .get(idx + 1)
                .map(|&(next_start, _)| next_start - 1)
                .unwrap_or(self.height);
            if end >= lower && start <= self.height {
                if diff > best {
                    best = diff;
                }
            }
        }
        best
    }
}

/// Public statement proved for any contiguous segment `[start_height ..= end_height]`
/// (either a single leaf segment or an aggregated subtree of segments).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SegmentSummary {
    pub state_in: BoundaryState,
    pub state_out: BoundaryState,
    pub monoid: ScoreMonoid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegmentError {
    EmptySegment,
    Header(HeaderError),
    Daa(DaaError),
    Mmr(MmrError),
    GenesisMismatch,
    ParentLinkMismatch,
    HeightDiscontinuity,
    TimestampNotStrictlyIncreasing,
    WorkOverflow,
    CapGridOverflow,
    BoundaryMismatch,
    LegacyAllowanceExceeded,
    NotGenesisRooted,
    ProfileMismatch,
}

/// Verify a contiguous batch of canonical Ergo headers advancing `state_in` -> `state_out`,
/// returning the exact associative `SegmentSummary`.
pub fn verify_segment(
    state_in: BoundaryState,
    raw_headers: &[Vec<u8>],
    witnesses: &[HeaderPointWitness],
) -> Result<SegmentSummary, SegmentError> {
    if raw_headers.is_empty() {
        return Err(SegmentError::EmptySegment);
    }
    if raw_headers.len() != witnesses.len() {
        return Err(SegmentError::Header(HeaderError::MissingPointWitness));
    }
    let params = state_in.profile.params();
    let profile32 = mainnet_profile32();
    let window_span = params.window_l + params.k0;

    let mut st = state_in.clone();
    let mut monoid = ScoreMonoid::identity();

    for (raw, wit) in raw_headers.iter().zip(witnesses.iter()) {
        let header =
            Header::decode_with_witness(raw, wit, None).map_err(SegmentError::Header)?;
        let expected_height = st.height.checked_add(1).ok_or(SegmentError::HeightDiscontinuity)?;
        if header.height != expected_height {
            return Err(SegmentError::HeightDiscontinuity);
        }
        header.check_era_binding().map_err(SegmentError::Header)?;
        let header_id = blake2b256(raw);
        let diff = decode_compact(header.n_bits).map_err(SegmentError::Daa)?;

        let mut u_step = params
            .modern_cap(diff)
            .ok_or(SegmentError::CapGridOverflow)?;
        let q_step = u_step;

        if expected_height == 1 {
            if header_id != MAINNET_GENESIS_ID {
                return Err(SegmentError::GenesisMismatch);
            }
            // Genesis contributes 0 to cumulative work, seeds global envelope with initial & v2 reset constants.
            let init_cap = params
                .grid_ceil(INITIAL_DIFFICULTY.max(V2_RESET_DIFFICULTY))
                .ok_or(SegmentError::CapGridOverflow)?;
            u_step = u_step.max(init_cap);
            st.height = 1;
            st.tip_id = header_id;
            st.tip_timestamp = header.timestamp;
            st.tip_difficulty = diff;
            st.total_work = 0;
            st.u_global = st.u_global.max(u_step);
            monoid.push_origin(&params, 1, 0, st.u_global, u_step, q_step);
            continue;
        }

        // Height >= 2: check parent link, strictly increasing timestamp, exact contextual DAA
        if header.parent_id != st.tip_id {
            return Err(SegmentError::ParentLinkMismatch);
        }
        if header.timestamp <= st.tip_timestamp {
            return Err(SegmentError::TimestampNotStrictlyIncreasing);
        }
        let anchors_ref = if expected_height >= EIP37_FIRST_CHILD {
            &st.eip37_anchors
        } else {
            &st.legacy_anchors
        };
        let req_diff =
            required_difficulty(expected_height, st.tip_difficulty, anchors_ref)
                .map_err(SegmentError::Daa)?;
        if diff != req_diff {
            return Err(SegmentError::Daa(DaaError::DifficultyMismatch {
                expected: req_diff,
                got: diff,
            }));
        }

        let work_lo = st.total_work;
        let work_hi = work_lo.checked_add(diff).ok_or(SegmentError::WorkOverflow)?;

        // Append work-interval leaf to append-only SHA-256 MMR (NO `n` in leaf!)
        let leaf = hash_leaf(&profile32, expected_height, work_lo, work_hi, raw);
        st.mmr.push_leaf(leaf).map_err(SegmentError::Mmr)?;

        // Update state
        st.height = expected_height;
        st.tip_id = header_id;
        st.tip_timestamp = header.timestamp;
        st.tip_difficulty = diff;
        st.total_work = work_hi;
        if expected_height <= AUTOLYKOS_V1_LAST_HEIGHT {
            st.v1_work_t1 = work_hi;
        }
        if expected_height < params.modern_origin_start {
            st.early_v2_work_t2 = work_hi;
        }

        // Record epoch anchors for future DAA retargets
        if expected_height <= 843_776 && expected_height % LEGACY_EPOCH == 0 {
            BoundaryState::record_anchor(
                &mut st.legacy_anchors,
                DaaAnchor {
                    height: expected_height,
                    timestamp: header.timestamp,
                    difficulty: diff,
                },
            );
        }
        if expected_height >= 843_648 && expected_height % EIP37_EPOCH == 0 {
            BoundaryState::record_anchor(
                &mut st.eip37_anchors,
                DaaAnchor {
                    height: expected_height,
                    timestamp: header.timestamp,
                    difficulty: diff,
                },
            );
        }
        st.record_modern_band(expected_height, diff, window_span);

        // Appendix B legacy introduction bound `B_j` at height `j - k0` for `j = 1024*(q+1) <= 843_776`
        // (skipping `j = 417_792` overridden by v2 reset).
        let candidate_j = expected_height + params.k0;
        if candidate_j <= 843_776
            && candidate_j % LEGACY_EPOCH == 0
            && candidate_j != 417_792
            && candidate_j > LEGACY_EPOCH
        {
            let bj = appendix_b_legacy_bound(
                candidate_j,
                params.k0,
                diff,
                header.timestamp,
                &st.legacy_anchors,
            )
            .map_err(SegmentError::Daa)?;
            let bj_cap = params.grid_ceil(bj).ok_or(SegmentError::CapGridOverflow)?;
            u_step = u_step.max(bj_cap);
        }

        st.u_global = st.u_global.max(u_step);

        // Local cap at origin `expected_height`
        let v_local = if expected_height < params.modern_origin_start {
            st.u_global
        } else {
            let m_i = st.modern_window_max(expected_height, window_span);
            params.modern_cap(m_i).ok_or(SegmentError::CapGridOverflow)?
        };
        monoid.push_origin(&params, expected_height, work_hi, v_local, u_step, q_step);
    }

    Ok(SegmentSummary {
        state_in,
        state_out: st,
        monoid,
    })
}

/// Exact associative merge of `>= 1` contiguous `SegmentSummary` items (depth-2 fan-in tree!).
/// Runs identically natively and inside the OpenVM v2.1.0 aggregator guest.
pub fn merge_segments(children: &[SegmentSummary]) -> Result<SegmentSummary, SegmentError> {
    if children.is_empty() {
        return Err(SegmentError::EmptySegment);
    }
    let profile = children[0].state_in.profile;
    let params = profile.params();
    let mut acc_monoid = children[0].monoid;
    for w in children.windows(2) {
        if w[0].state_out.profile != profile || w[1].state_in.profile != profile {
            return Err(SegmentError::ProfileMismatch);
        }
        if w[0].state_out != w[1].state_in {
            return Err(SegmentError::BoundaryMismatch);
        }
        acc_monoid = ScoreMonoid::merge(&params, &acc_monoid, &w[1].monoid);
    }
    Ok(SegmentSummary {
        state_in: children[0].state_in.clone(),
        state_out: children.last().unwrap().state_out.clone(),
        monoid: acc_monoid,
    })
}

/// Evaluate exact sampled-mode eligibility at bootstrap height `b` (with `f = b + k0 - 1`)
/// given:
/// - `prefix_through_b`: proved segment `[1 ..= b]` (yields exact-tail summary `(W_B, A_B, T1, T2)`)
/// - `bridge_b_to_f`: proved segment `[b+1 ..= f]` (completes sampled origins through `f`)
/// - `suffix_f_to_n`: proved segment `[f+1 ..= n]` (supplies remaining work and cap updates only)
pub fn check_bootstrap_eligibility(
    prefix_through_b: &SegmentSummary,
    bridge_b_to_f: &SegmentSummary,
    suffix_f_to_n: &SegmentSummary,
) -> Result<BootstrapStatement, SegmentError> {
    let profile = prefix_through_b.state_in.profile;
    let params: ProfileParams = profile.params();
    if prefix_through_b.state_in != BoundaryState::initial(profile) {
        return Err(SegmentError::NotGenesisRooted);
    }
    if prefix_through_b.state_out != bridge_b_to_f.state_in
        || bridge_b_to_f.state_out != suffix_f_to_n.state_in
    {
        return Err(SegmentError::BoundaryMismatch);
    }
    let b = prefix_through_b.state_out.height;
    let f = bridge_b_to_f.state_out.height;
    let n = suffix_f_to_n.state_out.height;
    if f != b + params.k0 - 1 || n <= f {
        return Err(SegmentError::HeightDiscontinuity);
    }

    // Legacy v1 work allowance (eq. 15): T1 <= b1 * U_global(n)
    let u_global_n = suffix_f_to_n.state_out.u_global;
    let t1_n = suffix_f_to_n.state_out.v1_work_t1;
    if t1_n > params.legacy_allowance_b1.saturating_mul(u_global_n) {
        return Err(SegmentError::LegacyAllowanceExceeded);
    }

    // Sampled score over origins [1..=f] against caps through n:
    let up_to_f = merge_segments(&[prefix_through_b.clone(), bridge_b_to_f.clone()])?;
    let mut sampled_monoid = up_to_f.monoid;
    sampled_monoid.apply_suffix_caps(
        &params,
        suffix_f_to_n.monoid.u_global_contrib,
        suffix_f_to_n.monoid.q_modern_contrib,
    );
    let total_work_n = suffix_f_to_n.state_out.total_work;
    let sampled_eligible = total_work_n >= sampled_monoid.a_sampled;

    // Exact-tail 4-integer summary at bootstrap height b (eq. 26):
    let w_b = prefix_through_b.state_out.total_work;
    let a_b = prefix_through_b.monoid.a_exact;
    let t1 = prefix_through_b.state_out.v1_work_t1;
    let t2 = prefix_through_b.state_out.early_v2_work_t2;
    let f_work = total_work_n
        .checked_sub(bridge_b_to_f.state_out.total_work)
        .ok_or(SegmentError::WorkOverflow)?;
    let mmr_root = suffix_f_to_n
        .state_out
        .mmr_root()
        .map_err(SegmentError::Mmr)?;

    Ok(BootstrapStatement {
        profile,
        tip_height: n,
        tip_id: suffix_f_to_n.state_out.tip_id,
        tip_timestamp: suffix_f_to_n.state_out.tip_timestamp,
        total_work: total_work_n,
        mmr_root,
        bootstrap_height: b,
        bootstrap_id: prefix_through_b.state_out.tip_id,
        bootstrap_timestamp: prefix_through_b.state_out.tip_timestamp,
        bootstrap_difficulty: prefix_through_b.state_out.tip_difficulty,
        bootstrap_eip37_anchors: prefix_through_b.state_out.eip37_anchors.clone(),
        bootstrap_modern_bands: prefix_through_b.state_out.modern_bands.clone(),
        following_work_f: f_work,
        w_b,
        a_b,
        t1,
        t2,
        u_global: u_global_n,
        sampled_required_work: sampled_monoid.a_sampled,
        sampled_eligible,
    })
}

/// Complete certified public bootstrap statement `x` produced by the recursive STARK
/// and bound before deriving the geometric work audit.
///
/// Directly embeds the STARK-authenticated EIP-37 DAA anchors and modern sliding-window
/// difficulty bands at bootstrap height `b` so the exact-tail verifier consumes zero
/// unauthenticated context.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BootstrapStatement {
    pub profile: ProfileId,
    pub tip_height: u32,
    pub tip_id: [u8; 32],
    pub tip_timestamp: i64,
    pub total_work: u128,
    pub mmr_root: [u8; 32],
    pub bootstrap_height: u32,
    pub bootstrap_id: [u8; 32],
    pub bootstrap_timestamp: i64,
    pub bootstrap_difficulty: u128,
    pub bootstrap_eip37_anchors: Vec<DaaAnchor>,
    pub bootstrap_modern_bands: Vec<(u32, u128)>,
    pub following_work_f: u128,
    pub w_b: u128,
    pub a_b: u128,
    pub t1: u128,
    pub t2: u128,
    pub u_global: u128,
    pub sampled_required_work: u128,
    pub sampled_eligible: bool,
}
