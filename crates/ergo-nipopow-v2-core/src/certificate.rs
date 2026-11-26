//! Canonical V2 certificate envelope and deterministic light-client fork-choice comparator.

use alloc::vec::Vec;

use crate::audit::AuditBundle;
use crate::profile::ProfileId;
use crate::segment::BootstrapStatement;

/// Backend tag identifying the structural proof format inside a V2 certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StructuralBackend {
    /// OpenVM v2.1.0 transparent post-quantum SWIRL/WHIR recursive STARK (`VmStarkProof`, zkSecurity audited & Lean-verified).
    OpenVmSwirlV21 = 1,
    /// ZisK v1.4 transparent post-quantum DEEP-ALI + FRI/STIR recursive STARK
    /// (Goldilocks^3, BLAKE3-256, 128-bit `ethereum/soundcalc`, ~240–247 KiB compressed).
    ZiskStirV14 = 2,
    /// Heterogeneous Dual-Proof envelope carrying BOTH a ZisK v1.4 128-bit STIR proof AND
    /// an OpenVM v2.1.0 zkSecurity-audited/Lean-verified SWIRL+WHIR proof over the exact
    /// same `BootstrapStatement`. Serialized canonically via `DualStructuralProof` inside
    /// `V2Certificate::structural_proof` and jointly bound before deriving the work audit.
    DualZiskV14OpenVmV21 = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DualProofError {
    EmptyZiskProof,
    EmptyOpenVmProof,
    LengthOverflow,
    Truncated,
    TrailingBytes,
}

/// Canonical container for `StructuralBackend::DualZiskV14OpenVmV21`:
/// `BE32(len(zisk_proof)) || zisk_proof || BE32(len(openvm_proof)) || openvm_proof`.
///
/// Both proofs certify the identical `SHA-256(bincode(BootstrapStatement))` and are
/// jointly committed inside `V2Certificate::structural_proof` before audit sampling.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DualStructuralProof {
    pub zisk_proof: Vec<u8>,
    pub openvm_proof: Vec<u8>,
}

impl DualStructuralProof {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, DualProofError> {
        if self.zisk_proof.is_empty() {
            return Err(DualProofError::EmptyZiskProof);
        }
        if self.openvm_proof.is_empty() {
            return Err(DualProofError::EmptyOpenVmProof);
        }
        let z_len = u32::try_from(self.zisk_proof.len()).map_err(|_| DualProofError::LengthOverflow)?;
        let o_len = u32::try_from(self.openvm_proof.len()).map_err(|_| DualProofError::LengthOverflow)?;
        let total = 8usize
            .checked_add(self.zisk_proof.len())
            .and_then(|v| v.checked_add(self.openvm_proof.len()))
            .ok_or(DualProofError::LengthOverflow)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&z_len.to_be_bytes());
        out.extend_from_slice(&self.zisk_proof);
        out.extend_from_slice(&o_len.to_be_bytes());
        out.extend_from_slice(&self.openvm_proof);
        Ok(out)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DualProofError> {
        if bytes.len() < 4 {
            return Err(DualProofError::Truncated);
        }
        let z_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if z_len == 0 {
            return Err(DualProofError::EmptyZiskProof);
        }
        let z_end = 4usize.checked_add(z_len).ok_or(DualProofError::Truncated)?;
        if bytes.len() < z_end + 4 {
            return Err(DualProofError::Truncated);
        }
        let zisk_proof = bytes[4..z_end].to_vec();
        let o_len = u32::from_be_bytes([
            bytes[z_end],
            bytes[z_end + 1],
            bytes[z_end + 2],
            bytes[z_end + 3],
        ]) as usize;
        if o_len == 0 {
            return Err(DualProofError::EmptyOpenVmProof);
        }
        let o_start = z_end + 4;
        let o_end = o_start.checked_add(o_len).ok_or(DualProofError::Truncated)?;
        if bytes.len() < o_end {
            return Err(DualProofError::Truncated);
        }
        if bytes.len() > o_end {
            return Err(DualProofError::TrailingBytes);
        }
        let openvm_proof = bytes[o_start..o_end].to_vec();
        Ok(Self {
            zisk_proof,
            openvm_proof,
        })
    }
}

/// Complete canonical NiPoPoW V2 bootstrap certificate (self-contained, witness-free,
/// zero unauthenticated context — all DAA anchors and sliding difficulty bands at `b`
/// are STARK-certified inside `statement`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct V2Certificate {
    pub magic: [u8; 8], // b"NPV2MMR1"
    pub backend: StructuralBackend,
    pub statement: BootstrapStatement,
    /// Complete structural proof bytes `pi_s` (bound BEFORE deriving the work audit!).
    pub structural_proof: Vec<u8>,
    /// Deduplicated native work-audit openings + MMR multiproof.
    pub audit: AuditBundle,
}

pub const CERT_MAGIC: [u8; 8] = *b"NPV2MMR1";

/// Deterministic candidate selection (Section 1):
/// - Filter to admitted candidates matching the requested `profile` and `query_height`
/// - Choose greatest certified cumulative work
/// - Break equal-work ties by lexicographically smallest complete canonical object bytes
/// - Return `None` (`NO_RESULT`) if no candidate is admitted
pub struct AdmittedCandidate<'a> {
    pub profile: ProfileId,
    pub query_height: u32,
    pub certified_work: u128,
    pub header_id: [u8; 32],
    pub canonical_bytes: &'a [u8],
}

pub fn select_best<'a>(
    requested_profile: ProfileId,
    requested_query: u32,
    candidates: &'a [AdmittedCandidate<'a>],
) -> Option<&'a AdmittedCandidate<'a>> {
    let mut best: Option<&'a AdmittedCandidate<'a>> = None;
    for cand in candidates {
        if cand.profile != requested_profile || cand.query_height != requested_query {
            continue;
        }
        best = match best {
            None => Some(cand),
            Some(cur) => {
                if cand.certified_work > cur.certified_work
                    || (cand.certified_work == cur.certified_work
                        && cand.canonical_bytes < cur.canonical_bytes)
                {
                    Some(cand)
                } else {
                    Some(cur)
                }
            }
        };
    }
    best
}
