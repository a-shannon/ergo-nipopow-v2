//! Exact recent-chain continuation verifier (Section 10, eq. 26–27).
//!
//! Verifies a complete modern tail `Q` after an authenticated bootstrap checkpoint `B`,
//! using ONLY STARK-authenticated EIP-37 DAA anchors and modern difficulty bands embedded
//! directly in `BootstrapStatement` (zero unauthenticated context!):
//! - Canonical Ergo header encoding, height sequence, parent hash linkage, strict timestamps
//! - Exact EIP-37 contextual difficulty across the boundary using STARK-authenticated DAA anchors
//! - Full native Autolykos v2 PoW on every new tail header
//! - Exact 4-integer old-origin guard (eq. 27) + every new origin guard in `[b+1..=f]`!

use alloc::vec::Vec;

use crate::daa::{decode_compact, required_difficulty, DaaAnchor, DaaError, EIP37_EPOCH};
use crate::header::{blake2b256, Header, HeaderError};
use crate::segment::BootstrapStatement;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TailError {
    BootstrapNotEligible,
    BootstrapNotModern,
    QueryOutOfRange,
    InsufficientDepth,
    InvalidContext,
    Header(HeaderError),
    Daa(DaaError),
    #[cfg(feature = "native-pow")]
    Pow(crate::pow::NativePowError),
    ParentLinkMismatch,
    TimestampNotIncreasing,
    WorkOverflow,
    CapGridOverflow,
    MaturityGuardNotSatisfied {
        total_work: u128,
        required_work: u128,
    },
}

/// Verified exact-tail continuation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTail {
    pub query_height: u32,
    pub query_header_id: [u8; 32],
    pub query_raw: Vec<u8>,
    pub tip_height: u32,
    pub tip_id: [u8; 32],
    pub total_work: u128,
}

fn lookup_band_difficulty(bands: &[(u32, u128)], height: u32) -> Option<u128> {
    if bands.is_empty() || height < bands[0].0 {
        return None;
    }
    let idx = bands.partition_point(|&(start, _)| start <= height);
    if idx == 0 {
        return None;
    }
    Some(bands[idx - 1].1)
}

/// Verify an exact modern continuation `tail_headers` after STARK-authenticated `bootstrap`
/// for `query_height`. Consumes zero unauthenticated side-channel context.
#[cfg(feature = "native-pow")]
pub fn verify_exact_tail(
    bootstrap: &BootstrapStatement,
    tail_headers: &[Vec<u8>],
    query_height: u32,
) -> Result<VerifiedTail, TailError> {
    if !bootstrap.sampled_eligible {
        return Err(TailError::BootstrapNotEligible);
    }
    let params = bootstrap.profile.params();
    let b = bootstrap.bootstrap_height;
    let window_span = (params.window_l + params.k0) as usize;
    if b < params.modern_origin_start {
        return Err(TailError::BootstrapNotModern);
    }

    // Validate STARK-authenticated EIP-37 anchor ring at height b
    if bootstrap.bootstrap_eip37_anchors.len() != 9 {
        return Err(TailError::InvalidContext);
    }
    for w in bootstrap.bootstrap_eip37_anchors.windows(2) {
        if w[1].height != w[0].height + EIP37_EPOCH || w[1].timestamp <= w[0].timestamp {
            return Err(TailError::InvalidContext);
        }
    }
    let last_epoch_le_b = b - (b % EIP37_EPOCH);
    if bootstrap.bootstrap_eip37_anchors.last().unwrap().height != last_epoch_le_b {
        return Err(TailError::InvalidContext);
    }

    // Validate STARK-authenticated modern difficulty bands covering [b + 1 - window_span ..= b]
    let bands = &bootstrap.bootstrap_modern_bands;
    let h0 = b
        .checked_add(1)
        .and_then(|v| v.checked_sub(window_span as u32))
        .ok_or(TailError::InvalidContext)?;
    if bands.is_empty() || bands[0].0 > h0 || bands.last().unwrap().0 > b {
        return Err(TailError::InvalidContext);
    }
    for w in bands.windows(2) {
        if w[1].0 <= w[0].0 {
            return Err(TailError::InvalidContext);
        }
    }
    if lookup_band_difficulty(bands, b) != Some(bootstrap.bootstrap_difficulty) {
        return Err(TailError::InvalidContext);
    }

    let n = b
        .checked_add(tail_headers.len() as u32)
        .ok_or(TailError::QueryOutOfRange)?;
    if query_height < b || query_height > n {
        return Err(TailError::QueryOutOfRange);
    }
    let f = query_height
        .checked_add(params.k0 - 1)
        .ok_or(TailError::QueryOutOfRange)?;
    if n < f {
        return Err(TailError::InsufficientDepth);
    }

    // Reconstruct exact sliding difficulty array `[h0..=b | b+1..=n]` from authenticated bands
    let mut diffs = Vec::with_capacity(window_span + tail_headers.len());
    for h in h0..=b {
        let d = lookup_band_difficulty(bands, h).ok_or(TailError::InvalidContext)?;
        diffs.push(d);
    }

    let mut eip_anchors: Vec<DaaAnchor> = bootstrap.bootstrap_eip37_anchors.clone();
    let mut parent_id = bootstrap.bootstrap_id;
    let mut prev_timestamp = bootstrap.bootstrap_timestamp;
    let mut prev_difficulty = bootstrap.bootstrap_difficulty;
    let mut total_work = bootstrap.w_b;
    let mut tail_work_prefix = Vec::with_capacity(tail_headers.len());
    let mut query_raw = Vec::new();
    let mut query_id = if query_height == b {
        bootstrap.bootstrap_id
    } else {
        [0u8; 32]
    };
    let mut max_tail_diff = 0u128;

    for (idx, raw) in tail_headers.iter().enumerate() {
        let expected_h = b + 1 + idx as u32;
        let (header, _) = Header::decode_native(raw, None).map_err(TailError::Header)?;
        if header.height != expected_h {
            return Err(TailError::Header(HeaderError::HeightOutOfRange));
        }
        header.check_era_binding().map_err(TailError::Header)?;
        if header.parent_id != parent_id {
            return Err(TailError::ParentLinkMismatch);
        }
        if header.timestamp <= prev_timestamp {
            return Err(TailError::TimestampNotIncreasing);
        }
        let diff = decode_compact(header.n_bits).map_err(TailError::Daa)?;
        let req = required_difficulty(expected_h, prev_difficulty, &eip_anchors)
            .map_err(TailError::Daa)?;
        if diff != req {
            return Err(TailError::Daa(DaaError::DifficultyMismatch {
                expected: req,
                got: diff,
            }));
        }
        crate::pow::verify_header_pow(&header).map_err(TailError::Pow)?;

        let id = blake2b256(raw);
        total_work = total_work
            .checked_add(diff)
            .ok_or(TailError::WorkOverflow)?;
        tail_work_prefix.push(total_work);
        if diff > max_tail_diff {
            max_tail_diff = diff;
        }
        diffs.push(diff);

        if expected_h % EIP37_EPOCH == 0 {
            if eip_anchors.len() == 9 {
                eip_anchors.remove(0);
            }
            eip_anchors.push(DaaAnchor {
                height: expected_h,
                timestamp: header.timestamp,
                difficulty: diff,
            });
        }
        if expected_h == query_height {
            query_raw = raw.clone();
            query_id = id;
        }
        parent_id = id;
        prev_timestamp = header.timestamp;
        prev_difficulty = diff;
    }

    // Check eq. (27): exact 4-integer old-origin guard for all origins i <= b
    let q_tail = if max_tail_diff == 0 {
        1u128
    } else {
        params
            .modern_cap(max_tail_diff)
            .ok_or(TailError::CapGridOverflow)?
    };
    let mut required = bootstrap
        .a_b
        .max(bootstrap.t1.saturating_add(params.m_exact[0].saturating_mul(q_tail)))
        .max(bootstrap.t2.saturating_add(params.m_exact[1].saturating_mul(q_tail)))
        .max(bootstrap.w_b.saturating_add(params.m_exact[2].saturating_mul(q_tail)));

    // Check every new origin i in (b, f] directly using exact sliding window [i - window_span, n]
    if f > b {
        let mut suffix_max = alloc::vec![0u128; diffs.len()];
        let mut run_max = 0u128;
        for i in (0..diffs.len()).rev() {
            if diffs[i] > run_max {
                run_max = diffs[i];
            }
            suffix_max[i] = run_max;
        }
        for origin in (b + 1)..=f {
            let tail_idx = (origin - b - 1) as usize;
            let row_idx = window_span + tail_idx;
            let win_start = row_idx - window_span;
            let m_i = suffix_max[win_start];
            let v_i = params
                .modern_cap(m_i)
                .ok_or(TailError::CapGridOverflow)?;
            let req_i = tail_work_prefix[tail_idx]
                .saturating_add(params.m_exact[2].saturating_mul(v_i));
            if req_i > required {
                required = req_i;
            }
        }
    }

    if total_work < required {
        return Err(TailError::MaturityGuardNotSatisfied {
            total_work,
            required_work: required,
        });
    }

    Ok(VerifiedTail {
        query_height,
        query_header_id: query_id,
        query_raw,
        tip_height: n,
        tip_id: parent_id,
        total_work,
    })
}
