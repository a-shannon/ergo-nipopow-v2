//! OpenVM v2.1.0 Level-2 (Root) recursive STARK aggregator guest.
//!
//! Cryptographically pins `EXPECTED_L1_EXE_COMMIT` and `EXPECTED_L1_VM_COMMIT` at
//! compile time (in `pinned_l1.rs`), verifies all Level-1 STARK proofs covering
//! `[1..=b]`, `[b+1..=f]`, and `[f+1..=n]`, executes `check_bootstrap_eligibility`,
//! enforces `stmt.sampled_eligible == true`, and reveals the 32-byte
//! `SHA-256(bincode(BootstrapStatement))`!

mod pinned_l1;

use ergo_nipopow_v2_core::mmr::sha256_bytes;
use ergo_nipopow_v2_core::segment::{
    check_bootstrap_eligibility, merge_segments, SegmentSummary,
};
use openvm::io::{read_vec, reveal_bytes32};
use openvm_verify_stark_guest::{verify_stark, ProofOutput};

#[derive(serde::Deserialize)]
struct ChildClaim {
    proof_commit: [u8; 32],
    summary: SegmentSummary,
}

#[derive(serde::Deserialize)]
struct RootInput {
    prefix_children: Vec<ChildClaim>,
    bridge_child: ChildClaim,
    suffix_children: Vec<ChildClaim>,
}

fn verify_l1(child: ChildClaim) -> SegmentSummary {
    let summary_bytes = bincode::serialize(&child.summary).expect("serialize L1 summary");
    let expected_pv = sha256_bytes(&summary_bytes);
    let expected = ProofOutput {
        app_exe_commit: pinned_l1::EXPECTED_L1_EXE_COMMIT,
        app_vm_commit: pinned_l1::EXPECTED_L1_VM_COMMIT,
        user_public_values: expected_pv.to_vec(),
    };
    verify_stark::<0>(&child.proof_commit, &expected);
    child.summary
}

fn main() {
    let raw = read_vec();
    let input: RootInput = bincode::deserialize(&raw).expect("valid RootInput");
    assert!(!input.prefix_children.is_empty(), "empty prefix children");
    assert!(!input.suffix_children.is_empty(), "empty suffix children");

    let mut prefix_sums = Vec::with_capacity(input.prefix_children.len());
    for c in input.prefix_children {
        prefix_sums.push(verify_l1(c));
    }
    let prefix_b = merge_segments(&prefix_sums).expect("merge prefix through b");
    let bridge = verify_l1(input.bridge_child);

    let mut suffix_sums = Vec::with_capacity(input.suffix_children.len());
    for c in input.suffix_children {
        suffix_sums.push(verify_l1(c));
    }
    let suffix = merge_segments(&suffix_sums).expect("merge suffix f..n");

    let stmt = check_bootstrap_eligibility(&prefix_b, &bridge, &suffix)
        .expect("bootstrap eligibility failed");
    assert!(stmt.sampled_eligible, "bootstrap height not sampled-eligible");

    let stmt_bytes = bincode::serialize(&stmt).expect("serialize BootstrapStatement");
    reveal_bytes32(sha256_bytes(&stmt_bytes));
}
