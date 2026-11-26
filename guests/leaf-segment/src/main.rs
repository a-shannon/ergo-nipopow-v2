//! OpenVM v2.1.0 transparent post-quantum SWIRL/WHIR leaf-segment guest.
//!
//! Reads a raw bincode-encoded `GuestSegmentInput` from OpenVM stdin, verifies every
//! Ergo header (canonical codec, secp256k1 point witness, BLAKE2b header ID, parent link,
//! consecutive height, strict timestamp, era binding, exact all-era contextual DAA,
//! Appendix B legacy envelope, append-only SHA-256 Work-Interval MMR via hardware
//! precompile, and exact associative maturity-guard monoid), and reveals the 32-byte
//! SHA-256 digest of the canonical `SegmentSummary` as the STARK public output.

use ergo_nipopow_v2_core::header::HeaderPointWitness;
use ergo_nipopow_v2_core::mmr::sha256_bytes;
use ergo_nipopow_v2_core::segment::{verify_segment, BoundaryState};
use openvm::io::{read_vec, reveal_bytes32};

#[derive(serde::Deserialize)]
struct GuestSegmentInput {
    state_in: BoundaryState,
    raw_headers: Vec<Vec<u8>>,
    witnesses: Vec<HeaderPointWitness>,
}

fn main() {
    let raw_input = read_vec();
    let input: GuestSegmentInput =
        bincode::deserialize(&raw_input).expect("valid bincode GuestSegmentInput");
    let summary = verify_segment(input.state_in, &input.raw_headers, &input.witnesses)
        .expect("Ergo mainnet segment verification failed");
    let summary_bytes = bincode::serialize(&summary).expect("canonical summary serialize");
    let commitment = sha256_bytes(&summary_bytes);
    reveal_bytes32(commitment);
}
