//! ZisK v1.4.0-alpha Level-1 recursive STARK aggregator guest.
//!
//! Compile-time pins `EXPECTED_LEAF_PROGRAM_VK` (leaf ROM root) and the trusted
//! ZisK v1.4.0-alpha BLAKE3 release setup VK (`VADCOP_FINAL_*_VK_BLAKE3`), verifies
//! every child leaf proof in-place via `zisk_verifier::verify_saved_words`, binds
//! each child's revealed 32-byte digest to `SHA-256(bincode(child.summary))`,
//! merges the contiguous summaries via `merge_segments`, and commits the merged
//! 32-byte summary commitment.

#![no_main]
ziskos::entrypoint!(main);

extern crate alloc;
use alloc::vec::Vec;

mod pinned_leaf;

use ergo_nipopow_v2_core::mmr::sha256_bytes;
use ergo_nipopow_v2_core::segment::{merge_segments, SegmentSummary};
use zisk_verifier::keys::{VADCOP_FINAL_COMPRESSED_VK_BLAKE3, VADCOP_FINAL_VK_BLAKE3};

#[derive(serde::Deserialize)]
struct ZiskChildClaim {
    /// Raw ZisK saved proof as little-endian u64 words (seed trailer stripped on host).
    proof_words: Vec<u64>,
    summary: SegmentSummary,
}

#[derive(serde::Deserialize)]
struct ZiskL1Input {
    children: Vec<ZiskChildClaim>,
}

fn main() {
    let raw = ziskos::io::read_slice();
    let input: ZiskL1Input = bincode::deserialize(raw).expect("valid ZiskL1Input");
    assert!(!input.children.is_empty(), "empty L1 batch");
    assert_ne!(
        pinned_leaf::EXPECTED_LEAF_PROGRAM_VK,
        [0, 0, 0, 0],
        "leaf program VK must be pinned at compile time"
    );

    let setup_vk = if pinned_leaf::EXPECT_COMPRESSED_LEAF {
        &VADCOP_FINAL_COMPRESSED_VK_BLAKE3
    } else {
        &VADCOP_FINAL_VK_BLAKE3
    };

    let mut summaries = Vec::with_capacity(input.children.len());
    for child in input.children {
        let verified = zisk_verifier::verify_saved_words(
            &child.proof_words,
            setup_vk,
            Some(&pinned_leaf::EXPECTED_LEAF_PROGRAM_VK),
        )
        .expect("child ZisK STARK proof verification failed");

        let outs = verified.outputs_u32().expect("expected leaf u32 outputs");
        let mut committed_digest = [0u8; 32];
        for i in 0..8 {
            committed_digest[i * 4..(i + 1) * 4].copy_from_slice(&outs[i].to_le_bytes());
        }

        let summary_bytes = bincode::serialize(&child.summary).expect("serialize child summary");
        let expected_digest = sha256_bytes(&summary_bytes);
        assert_eq!(
            committed_digest, expected_digest,
            "child proof public output digest mismatch"
        );
        summaries.push(child.summary);
    }

    let merged = merge_segments(&summaries).expect("contiguous L1 segment merge");
    let merged_bytes = bincode::serialize(&merged).expect("serialize merged L1 summary");
    let merged_commitment = sha256_bytes(&merged_bytes);
    ziskos::io::commit_slice(&merged_commitment);
}
