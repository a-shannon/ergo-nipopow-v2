//! ZisK v1.4.0-alpha Level-2 (Root) recursive STARK aggregator guest.
//!
//! Compile-time pins `EXPECTED_L1_PROGRAM_VK` (ROM root of `ergo-nipopow-v2-zisk-agg-l1`)
//! and the trusted ZisK v1.4.0-alpha BLAKE3 release setup VK (`VADCOP_FINAL_*_VK_BLAKE3`),
//! verifies every Level-1 child proof covering `[1..=b]`, `[b+1..=f]`, and `[f+1..=n]`
//! in-place via `zisk_verifier::verify_saved_words`, binds each child's revealed 32-byte
//! digest to `SHA-256(bincode(child.summary))`, runs `check_bootstrap_eligibility`,
//! enforces `stmt.sampled_eligible == true`, and commits `SHA-256(bincode(&stmt))`.

#![no_main]
ziskos::entrypoint!(main);

extern crate alloc;
use alloc::vec::Vec;

mod pinned_l1;

use ergo_nipopow_v2_core::mmr::sha256_bytes;
use ergo_nipopow_v2_core::segment::{
    check_bootstrap_eligibility, merge_segments, SegmentSummary,
};
use zisk_verifier::keys::{VADCOP_FINAL_COMPRESSED_VK_BLAKE3, VADCOP_FINAL_VK_BLAKE3};

#[derive(serde::Deserialize)]
struct ZiskChildClaim {
    /// Raw ZisK saved proof as little-endian u64 words (seed trailer stripped on host).
    proof_words: Vec<u64>,
    summary: SegmentSummary,
}

#[derive(serde::Deserialize)]
struct ZiskRootInput {
    prefix_children: Vec<ZiskChildClaim>,
    bridge_child: ZiskChildClaim,
    suffix_children: Vec<ZiskChildClaim>,
}

fn verify_l1(child: ZiskChildClaim, setup_vk: &[u64; 4]) -> SegmentSummary {
    let verified = zisk_verifier::verify_saved_words(
        &child.proof_words,
        setup_vk,
        Some(&pinned_l1::EXPECTED_L1_PROGRAM_VK),
    )
    .expect("child L1 ZisK STARK proof verification failed");

    let outs = verified.outputs_u32().expect("expected L1 u32 outputs");
    let mut committed_digest = [0u8; 32];
    for i in 0..8 {
        committed_digest[i * 4..(i + 1) * 4].copy_from_slice(&outs[i].to_le_bytes());
    }

    let summary_bytes = bincode::serialize(&child.summary).expect("serialize L1 summary");
    let expected_digest = sha256_bytes(&summary_bytes);
    assert_eq!(
        committed_digest, expected_digest,
        "child L1 proof public output digest mismatch"
    );
    child.summary
}

fn main() {
    let raw = ziskos::io::read_slice();
    let input: ZiskRootInput = bincode::deserialize(raw).expect("valid ZiskRootInput");
    assert!(!input.prefix_children.is_empty(), "empty prefix children");
    assert!(!input.suffix_children.is_empty(), "empty suffix children");
    assert_ne!(
        pinned_l1::EXPECTED_L1_PROGRAM_VK,
        [0, 0, 0, 0],
        "L1 program VK must be pinned at compile time"
    );

    let setup_vk = if pinned_l1::EXPECT_COMPRESSED_L1 {
        &VADCOP_FINAL_COMPRESSED_VK_BLAKE3
    } else {
        &VADCOP_FINAL_VK_BLAKE3
    };

    let mut prefix_sums = Vec::with_capacity(input.prefix_children.len());
    for c in input.prefix_children {
        prefix_sums.push(verify_l1(c, setup_vk));
    }
    let prefix_b = merge_segments(&prefix_sums).expect("merge prefix through b");
    let bridge = verify_l1(input.bridge_child, setup_vk);

    let mut suffix_sums = Vec::with_capacity(input.suffix_children.len());
    for c in input.suffix_children {
        suffix_sums.push(verify_l1(c, setup_vk));
    }
    let suffix = merge_segments(&suffix_sums).expect("merge suffix f..n");

    let stmt = check_bootstrap_eligibility(&prefix_b, &bridge, &suffix)
        .expect("bootstrap eligibility failed");
    assert!(stmt.sampled_eligible, "bootstrap height not sampled-eligible");

    let stmt_bytes = bincode::serialize(&stmt).expect("serialize BootstrapStatement");
    let root_commitment = sha256_bytes(&stmt_bytes);
    ziskos::io::commit_slice(&root_commitment);
}
