//! OpenVM v2.1.0 Level-1 recursive STARK aggregator guest.
//!
//! Cryptographically pins `EXPECTED_LEAF_EXE_COMMIT` and `EXPECTED_LEAF_VM_COMMIT`
//! at compile time (in `pinned_leaf.rs`) so no untrusted child program can be substituted.

mod pinned_leaf;

use ergo_nipopow_v2_core::mmr::sha256_bytes;
use ergo_nipopow_v2_core::segment::{merge_segments, SegmentSummary};
use openvm::io::{read_vec, reveal_bytes32};
use openvm_verify_stark_guest::{verify_stark, ProofOutput};

#[derive(serde::Deserialize)]
struct ChildClaim {
    proof_commit: [u8; 32],
    summary: SegmentSummary,
}

#[derive(serde::Deserialize)]
struct L1Input {
    children: Vec<ChildClaim>,
}

fn main() {
    let raw = read_vec();
    let input: L1Input = bincode::deserialize(&raw).expect("valid L1Input");
    assert!(!input.children.is_empty(), "empty L1 batch");

    let mut summaries = Vec::with_capacity(input.children.len());
    for child in input.children {
        let summary_bytes = bincode::serialize(&child.summary).expect("serialize summary");
        let expected_pv = sha256_bytes(&summary_bytes);
        let expected = ProofOutput {
            app_exe_commit: pinned_leaf::EXPECTED_LEAF_EXE_COMMIT,
            app_vm_commit: pinned_leaf::EXPECTED_LEAF_VM_COMMIT,
            user_public_values: expected_pv.to_vec(),
        };
        verify_stark::<0>(&child.proof_commit, &expected);
        summaries.push(child.summary);
    }

    let merged = merge_segments(&summaries).expect("contiguous L1 segment merge");
    let merged_bytes = bincode::serialize(&merged).expect("serialize merged L1 summary");
    reveal_bytes32(sha256_bytes(&merged_bytes));
}
