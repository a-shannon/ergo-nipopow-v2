//! Pre-audit geometric work-coordinate sampler and canonical deduplicated MMR
//! multiproof + native Autolykos PoW audit verifier.

use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use sha2::{Digest, Sha512};

use crate::daa::decode_compact;
use crate::header::{Header, HeaderError};
use crate::mmr::{hash_leaf, mainnet_profile32, work_to_be28, MmrError, MmrMultiproof, MmrStore};
use crate::profile::ProfileParams;
use crate::segment::BootstrapStatement;

const AUDIT_NAMESPACE_TAG: &[u8] = b"Ergo-NiPoPoW-V2/audit/v2/1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    EmptyStructuralField,
    InvalidScaleRange,
    SamplerExhausted,
    CoordinateOverflow,
    EmptyOpenings,
    TooManyOpenings,
    UnorderedIntervals,
    IntervalLengthMismatch,
    CoordinateNotCovered,
    UnusedSamplesOrOpenings,
    Header(HeaderError),
    Mmr(MmrError),
    #[cfg(feature = "native-pow")]
    Pow(crate::pow::NativePowError),
}

/// Derive all sorted work-audit coordinates from the complete canonical statement `x_bytes`
/// and complete structural proof `proof_bytes` (Section 4, eq. 3).
pub fn derive_audit_coordinates(
    params: &ProfileParams,
    x_bytes: &[u8],
    proof_bytes: &[u8],
    total_work: u128,
    following_work_f: u128,
) -> Result<Vec<u128>, AuditError> {
    if x_bytes.is_empty() || proof_bytes.is_empty() {
        return Err(AuditError::EmptyStructuralField);
    }
    if following_work_f == 0 || following_work_f > total_work {
        return Err(AuditError::InvalidScaleRange);
    }
    let mut prefix = Sha512::new();
    prefix.update(AUDIT_NAMESPACE_TAG);
    for field in [x_bytes, proof_bytes] {
        prefix.update((field.len() as u64).to_be_bytes());
        prefix.update(field);
    }

    let total_bi = BigUint::from(total_work);
    let mut scale_bi = BigUint::from(following_work_f);
    let space = BigUint::from(1u8) << 512usize;
    let mut coords = Vec::new();

    loop {
        let cutoff = &space - (&space % &scale_bi);
        let start = &total_bi - &scale_bi;
        let scale_u128 = scale_bi.to_u128().ok_or(AuditError::CoordinateOverflow)?;
        let mut scale_state = prefix.clone();
        scale_state.update(work_to_be28(scale_u128));

        for j in 0..params.draws_per_scale {
            let mut idx_state = scale_state.clone();
            idx_state.update(j.to_be_bytes());
            let mut picked = None;
            for attempt in [1u32, 2u32] {
                let mut st = idx_state.clone();
                st.update(attempt.to_be_bytes());
                let digest: [u8; 64] = st.finalize().into();
                let val = BigUint::from_bytes_be(&digest);
                if val < cutoff {
                    let c = (&start + (val % &scale_bi))
                        .to_u128()
                        .ok_or(AuditError::CoordinateOverflow)?;
                    picked = Some(c);
                    break;
                }
            }
            coords.push(picked.ok_or(AuditError::SamplerExhausted)?);
        }

        if scale_bi == total_bi {
            break;
        }
        scale_bi = (&scale_bi << 1usize).min(total_bi.clone());
    }
    coords.sort_unstable();
    Ok(coords)
}

/// One sampled work interval opening (header bytes + exact interval bounds).
/// Note: sibling hashes are NOT duplicated per opening — they live once in `AuditBundle::multiproof`!
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SampledLeaf {
    pub height: u32,
    pub work_lo: u128,
    pub work_hi: u128,
    pub raw_header: Vec<u8>,
}

/// Complete deduplicated native work-audit payload attached to a V2 certificate.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditBundle {
    pub leaves: Vec<SampledLeaf>,
    pub multiproof: MmrMultiproof,
}

impl AuditBundle {
    /// Approximate compact binary wire size (without JSON overhead):
    /// 4B count + per leaf (4B height + 28B lo + 28B hi + 2B len + raw) + deduplicated multiproof.
    pub fn compact_wire_bytes(&self) -> usize {
        let leaves_bytes: usize = self
            .leaves
            .iter()
            .map(|l| 4 + 28 + 28 + 2 + l.raw_header.len())
            .sum();
        4 + leaves_bytes + self.multiproof.encoded_bytes()
    }
}

/// Producer helper: construct the minimal deduplicated `AuditBundle` for a verified `BootstrapStatement`.
pub fn build_audit_bundle(
    statement: &BootstrapStatement,
    x_bytes: &[u8],
    proof_bytes: &[u8],
    mmr_store: &MmrStore,
    raw_headers: &[Vec<u8>],
    cumulative_work: &[u128], // cumulative_work[h - 1] = W(h), with cumulative_work[0] = 0
) -> Result<AuditBundle, AuditError> {
    let params = statement.profile.params();
    let samples = derive_audit_coordinates(
        &params,
        x_bytes,
        proof_bytes,
        statement.total_work,
        statement.following_work_f,
    )?;

    let n = statement.tip_height as usize;
    let mut leaves = Vec::new();
    let mut positions = Vec::new();
    let mut cursor = 0usize;

    while cursor < samples.len() {
        let coord = samples[cursor];
        // Binary search for height h in 2..=n with W(h-1) <= coord < W(h)
        let (mut lo, mut hi) = (2usize, n);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if cumulative_work[mid - 1] <= coord {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let h = lo;
        let w_lo = cumulative_work[h - 2];
        let w_hi = cumulative_work[h - 1];
        if !(w_lo <= coord && coord < w_hi) {
            return Err(AuditError::CoordinateNotCovered);
        }
        positions.push((h - 2) as u64);
        leaves.push(SampledLeaf {
            height: h as u32,
            work_lo: w_lo,
            work_hi: w_hi,
            raw_header: raw_headers[h - 1].clone(),
        });
        cursor += samples[cursor..].partition_point(|&c| c < w_hi);
    }

    let multiproof = mmr_store
        .generate_multiproof(&positions)
        .map_err(AuditError::Mmr)?;
    Ok(AuditBundle { leaves, multiproof })
}

/// Standalone light-client verifier for the complete native work audit:
/// 1. Re-derives all geometric work coordinates from `(x_bytes, proof_bytes)`.
/// 2. Checks strict ordering, positive exact difficulty interval `work_hi - work_lo == D(raw)`,
///    canonical Ergo header decoding + era binding, and complete native Autolykos v1/v2 PoW.
/// 3. Verifies ALL opened leaves simultaneously against `statement.mmr_root` via the
///    canonical deduplicated MMR multiproof.
#[cfg(feature = "native-pow")]
pub fn verify_audit_bundle(
    statement: &BootstrapStatement,
    x_bytes: &[u8],
    proof_bytes: &[u8],
    bundle: &AuditBundle,
) -> Result<usize, AuditError> {
    let params = statement.profile.params();
    let samples = derive_audit_coordinates(
        &params,
        x_bytes,
        proof_bytes,
        statement.total_work,
        statement.following_work_f,
    )?;
    if bundle.leaves.is_empty() {
        return Err(AuditError::EmptyOpenings);
    }
    if bundle.leaves.len() > samples.len() {
        return Err(AuditError::TooManyOpenings);
    }

    let p32 = mainnet_profile32();
    let mut mmr_leaves = Vec::with_capacity(bundle.leaves.len());
    let mut cursor = 0usize;
    let mut prev: Option<(u32, u128)> = None;

    for leaf in &bundle.leaves {
        if leaf.height < 2 || leaf.height > statement.tip_height {
            return Err(AuditError::UnorderedIntervals);
        }
        if let Some((prev_h, prev_hi)) = prev {
            if leaf.height <= prev_h || leaf.work_lo < prev_hi {
                return Err(AuditError::UnorderedIntervals);
            }
        }
        let coord = *samples
            .get(cursor)
            .ok_or(AuditError::UnusedSamplesOrOpenings)?;
        if !(leaf.work_lo <= coord && coord < leaf.work_hi) {
            return Err(AuditError::CoordinateNotCovered);
        }

        // Canonical Ergo header decode, era check, exact difficulty interval check, and native PoW
        let (header, _) =
            Header::decode_native(&leaf.raw_header, None).map_err(AuditError::Header)?;
        if header.height != leaf.height {
            return Err(AuditError::Header(HeaderError::HeightOutOfRange));
        }
        header.check_era_binding().map_err(AuditError::Header)?;
        let diff = decode_compact(header.n_bits)
            .map_err(|_| AuditError::IntervalLengthMismatch)?;
        if leaf.work_lo.checked_add(diff) != Some(leaf.work_hi) {
            return Err(AuditError::IntervalLengthMismatch);
        }
        crate::pow::verify_header_pow(&header).map_err(AuditError::Pow)?;

        let pos = (leaf.height - 2) as u64;
        let digest = hash_leaf(&p32, leaf.height, leaf.work_lo, leaf.work_hi, &leaf.raw_header);
        mmr_leaves.push((pos, digest));

        cursor += samples[cursor..].partition_point(|&c| c < leaf.work_hi);
        prev = Some((leaf.height, leaf.work_hi));
    }

    if cursor != samples.len() {
        return Err(AuditError::UnusedSamplesOrOpenings);
    }

    let leaf_count = (statement.tip_height - 1) as u64;
    bundle
        .multiproof
        .verify(&p32, leaf_count, &mmr_leaves, &statement.mmr_root)
        .map_err(AuditError::Mmr)?;

    Ok(samples.len())
}
