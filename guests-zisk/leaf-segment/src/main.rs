//! ZisK v1.4.0-alpha RV64IMA (128-bit `ethereum/soundcalc`, Goldilocks^3, BLAKE3-256)
//! leaf-segment guest for Ergo NiPoPoW V2 (`V2Production128`).
//!
//! Hardware-accelerated via ZisK's built-in `Sha256f` (MMR) and `Blake2br` (header ID)
//! precompiles (`ergo-nipopow-v2-core`, `no_std`, `features = ["zisk"]`).

#![no_main]
ziskos::entrypoint!(main);

extern crate alloc;
use alloc::vec::Vec;

use ergo_nipopow_v2_core::header::HeaderPointWitness;
use ergo_nipopow_v2_core::mmr::sha256_bytes;
use ergo_nipopow_v2_core::segment::{verify_segment, BoundaryState};

#[derive(serde::Deserialize)]
struct GuestSegmentInput {
    state_in: BoundaryState,
    raw_headers: Vec<Vec<u8>>,
    witnesses: Vec<HeaderPointWitness>,
}

fn main() {
    let raw_input = ziskos::io::read_slice();
    let input: GuestSegmentInput =
        bincode::deserialize(raw_input).expect("valid bincode GuestSegmentInput");
    let summary = verify_segment(input.state_in, &input.raw_headers, &input.witnesses)
        .expect("Ergo mainnet segment verification failed");
    let summary_bytes = bincode::serialize(&summary).expect("canonical summary serialize");
    let commitment = sha256_bytes(&summary_bytes);
    ziskos::io::commit_slice(&commitment);
}
