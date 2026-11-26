//! Isolated single-fault adversarial negative test suite for Ergo NiPoPoW V2 core.
//!
//! Every test flips ONE exact consensus/cryptographic invariant on genuine Ergo mainnet
//! headers and verifies fail-closed rejection at the intended error boundary.

use ergo_nipopow_v2_core::audit::{build_audit_bundle, verify_audit_bundle, AuditError};
use ergo_nipopow_v2_core::certificate::{
    select_best, AdmittedCandidate, DualProofError, DualStructuralProof,
};
use ergo_nipopow_v2_core::daa::{decode_compact, DaaError};
use ergo_nipopow_v2_core::header::{Header, HeaderError, HeaderPointWitness};
use ergo_nipopow_v2_core::mmr::{hash_leaf, mainnet_profile32, MmrError, MmrStore};
use ergo_nipopow_v2_core::profile::ProfileId;
use ergo_nipopow_v2_core::secp256k1::PointError;
use ergo_nipopow_v2_core::segment::{
    merge_segments, verify_segment, BoundaryState, SegmentError,
};

fn load_first_headers(count: usize) -> Vec<Vec<u8>> {
    let path = std::env::var("ERGO_HEADERS_U32LE").unwrap_or_else(|_| {
        format!(
            "{}/testdata/prefix-4096.u32le",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let data = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read canonical mainnet headers at {path}: {e}"));
    let mut out = Vec::with_capacity(count);
    let mut pos = 0usize;
    while out.len() < count && pos + 4 <= data.len() {
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        out.push(data[pos..pos + len].to_vec());
        pos += len;
    }
    assert_eq!(out.len(), count);
    out
}

fn decode_all(raws: &[Vec<u8>]) -> (Vec<Header>, Vec<HeaderPointWitness>) {
    let mut hdrs = Vec::with_capacity(raws.len());
    let mut wits = Vec::with_capacity(raws.len());
    for raw in raws {
        let (h, w) = Header::decode_native(raw, None).unwrap();
        hdrs.push(h);
        wits.push(w);
    }
    (hdrs, wits)
}

#[test]
fn real_genesis_prefix_positive_and_isolated_faults() {
    let raws = load_first_headers(16);
    let (hdrs, wits) = decode_all(&raws);
    let init = BoundaryState::initial(ProfileId::V2Production);

    // 1. Positive baseline + exact associative split parity
    let whole = verify_segment(init.clone(), &raws, &wits).unwrap();
    let left = verify_segment(init.clone(), &raws[..7], &wits[..7]).unwrap();
    let right = verify_segment(left.state_out.clone(), &raws[7..], &wits[7..]).unwrap();
    let merged = merge_segments(&[left.clone(), right.clone()]).unwrap();
    assert_eq!(whole, merged);

    // 2. Negative: bad genesis ID rejected
    let mut bad_gen_raws = raws.clone();
    let mut bad_gen_hdr = hdrs[0].clone();
    bad_gen_hdr.votes[0] ^= 1;
    bad_gen_raws[0] = bad_gen_hdr.encode().unwrap();
    assert_eq!(
        verify_segment(init.clone(), &bad_gen_raws, &wits),
        Err(SegmentError::GenesisMismatch)
    );

    // 3. Negative: broken parent link rejected
    let mut bad_parent_raws = raws.clone();
    let mut bad_child = hdrs[3].clone();
    bad_child.parent_id[0] ^= 1;
    bad_parent_raws[3] = bad_child.encode().unwrap();
    assert_eq!(
        verify_segment(init.clone(), &bad_parent_raws, &wits),
        Err(SegmentError::ParentLinkMismatch)
    );

    // 4. Negative: non-increasing timestamp rejected
    let mut bad_ts_raws = raws.clone();
    let mut bad_ts = hdrs[2].clone();
    bad_ts.timestamp = hdrs[1].timestamp;
    bad_ts_raws[2] = bad_ts.encode().unwrap();
    assert_eq!(
        verify_segment(init.clone(), &bad_ts_raws, &wits),
        Err(SegmentError::TimestampNotStrictlyIncreasing)
    );

    // 5. Negative: wrong contextual difficulty rejected
    let mut bad_diff_raws = raws.clone();
    let mut bad_diff = hdrs[4].clone();
    bad_diff.n_bits = bad_diff.n_bits.wrapping_add(1);
    bad_diff_raws[4] = bad_diff.encode().unwrap();
    assert!(matches!(
        verify_segment(init.clone(), &bad_diff_raws, &wits),
        Err(SegmentError::Daa(DaaError::DifficultyMismatch { .. }))
    ));

    // 6. Negative: tampered secp256k1 point witness rejected
    let mut bad_wits = wits.clone();
    bad_wits[1].pk_y[31] ^= 2; // preserves parity, breaks curve equation
    assert_eq!(
        verify_segment(init.clone(), &raws, &bad_wits),
        Err(SegmentError::Header(HeaderError::InvalidPoint(
            PointError::NotOnCurve
        )))
    );

    // 7. Negative: trailing byte on canonical header rejected
    let mut trailing = raws.clone();
    trailing[1].push(0x00);
    assert_eq!(
        verify_segment(init.clone(), &trailing, &wits),
        Err(SegmentError::Header(HeaderError::TrailingBytes))
    );

    // 8. Negative: non-contiguous segment merge rejected
    let mut broken_right = right.clone();
    broken_right.state_in.total_work += 1;
    assert_eq!(
        merge_segments(&[left.clone(), broken_right]),
        Err(SegmentError::BoundaryMismatch)
    );

    // 9. Negative: PoW version mismatch (v2 header in v1 era height <= 417791) rejected
    let mut bad_era = hdrs[5].clone();
    bad_era.version = 2;
    bad_era.pow = ergo_nipopow_v2_core::header::PowSolution::V2 {
        pk: match &hdrs[5].pow {
            ergo_nipopow_v2_core::header::PowSolution::V1 { pk, .. } => *pk,
            _ => unreachable!(),
        },
        nonce: [0u8; 8],
    };
    let mut bad_era_raws = raws.clone();
    bad_era_raws[5] = bad_era.encode().unwrap();
    let mut bad_era_wits = wits.clone();
    bad_era_wits[5].w_y = [0u8; 32];
    assert_eq!(
        verify_segment(init.clone(), &bad_era_raws, &bad_era_wits),
        Err(SegmentError::Header(HeaderError::EraVersionMismatch))
    );
}

#[test]
fn audit_bundle_and_comparator_negatives() {
    // Use 4,096 real mainnet headers so legacy retargets (2049, 3073) are exercised AND
    // sampled coordinates do not saturate every single header.
    let raws = load_first_headers(4096);
    let (hdrs, wits) = decode_all(&raws);
    let init = BoundaryState::initial(ProfileId::V2Production);
    let summary = verify_segment(init, &raws, &wits).unwrap();

    // Build MMR & cumulative work for this 4096-header prefix
    let p32 = mainnet_profile32();
    let mut store = MmrStore::new(4096);
    let mut cum = vec![0u128];
    let mut w = 0u128;
    for h in 2..=4096 {
        let d = decode_compact(hdrs[h - 1].n_bits).unwrap();
        let leaf = hash_leaf(&p32, h as u32, w, w + d, &raws[h - 1]);
        store.push_leaf(leaf);
        w += d;
        cum.push(w);
    }

    let stmt = ergo_nipopow_v2_core::segment::BootstrapStatement {
        profile: ProfileId::V2Production,
        tip_height: 4096,
        tip_id: summary.state_out.tip_id,
        tip_timestamp: summary.state_out.tip_timestamp,
        total_work: summary.state_out.total_work,
        mmr_root: summary.state_out.mmr_root().unwrap(),
        bootstrap_height: 3000,
        bootstrap_id: [0u8; 32],
        bootstrap_timestamp: 0,
        bootstrap_difficulty: 0,
        bootstrap_eip37_anchors: Vec::new(),
        bootstrap_modern_bands: Vec::new(),
        following_work_f: w / 2,
        w_b: cum[2999],
        a_b: 0,
        t1: w,
        t2: w,
        u_global: summary.state_out.u_global,
        sampled_required_work: 0,
        sampled_eligible: true,
    };

    let x_bytes = b"canonical-x";
    let pi_bytes = b"complete-pi-s";
    let bundle = build_audit_bundle(&stmt, x_bytes, pi_bytes, &store, &raws, &cum).unwrap();
    // Positive audit passes (including native Autolykos v1 PoW on every sampled header!)
    verify_audit_bundle(&stmt, x_bytes, pi_bytes, &bundle).unwrap();

    // Negative: changing structural proof bytes changes audit coordinates -> fails!
    assert!(verify_audit_bundle(&stmt, x_bytes, b"tampered-pi-s", &bundle).is_err());

    // Negative: tampering MMR sibling digest fails at RootMismatch
    let mut bad_sib = bundle.clone();
    if !bad_sib.multiproof.siblings.is_empty() {
        bad_sib.multiproof.siblings[0][0] ^= 1;
        assert_eq!(
            verify_audit_bundle(&stmt, x_bytes, pi_bytes, &bad_sib),
            Err(AuditError::Mmr(MmrError::RootMismatch))
        );
    }

    // Negative: tampering header PoW nonce fails native Autolykos PoW check!
    let mut bad_pow = bundle.clone();
    let (mut tampered_hdr, _) = Header::decode_native(&bad_pow.leaves[0].raw_header, None).unwrap();
    if let ergo_nipopow_v2_core::header::PowSolution::V1 { ref mut nonce, .. } = tampered_hdr.pow {
        nonce[0] ^= 1;
    }
    bad_pow.leaves[0].raw_header = tampered_hdr.encode().unwrap();
    assert!(matches!(
        verify_audit_bundle(&stmt, x_bytes, pi_bytes, &bad_pow),
        Err(AuditError::Pow(_))
    ));

    // Comparator: NO_RESULT on empty / wrong profile, max work wins, tie breaks lexicographically
    assert!(select_best(ProfileId::V2Production, 100, &[]).is_none());
    let c1 = AdmittedCandidate {
        profile: ProfileId::V2Production,
        query_height: 100,
        certified_work: 500,
        header_id: [1u8; 32],
        canonical_bytes: b"bbb",
    };
    let c2 = AdmittedCandidate {
        profile: ProfileId::V2Production,
        query_height: 100,
        certified_work: 500,
        header_id: [2u8; 32],
        canonical_bytes: b"aaa",
    };
    let c_wrong_profile = AdmittedCandidate {
        profile: ProfileId::V2LegacyR15,
        query_height: 100,
        certified_work: 9999,
        header_id: [3u8; 32],
        canonical_bytes: b"000",
    };
    let candidates = [c1, c2, c_wrong_profile];
    let winner = select_best(ProfileId::V2Production, 100, &candidates).unwrap();
    assert_eq!(winner.header_id, [2u8; 32]);
}

#[test]
fn v2_production_128_audit_dual_proof_and_profile_isolation() {
    let raws = load_first_headers(4096);
    let (hdrs, wits) = decode_all(&raws);
    let init = BoundaryState::initial(ProfileId::V2Production128);

    // 1. Positive segment + exact associative split parity under V2Production128
    let whole = verify_segment(init.clone(), &raws, &wits).unwrap();
    let left = verify_segment(init.clone(), &raws[..2048], &wits[..2048]).unwrap();
    let right = verify_segment(left.state_out.clone(), &raws[2048..], &wits[2048..]).unwrap();
    let merged = merge_segments(&[left, right]).unwrap();
    assert_eq!(whole, merged);

    // 2. Build MMR & verify full 982-draw-per-scale audit bundle under V2Production128
    let p32 = mainnet_profile32();
    let mut store = MmrStore::new(4096);
    let mut cum = vec![0u128];
    let mut w = 0u128;
    for h in 2..=4096 {
        let d = decode_compact(hdrs[h - 1].n_bits).unwrap();
        let leaf = hash_leaf(&p32, h as u32, w, w + d, &raws[h - 1]);
        store.push_leaf(leaf);
        w += d;
        cum.push(w);
    }

    let stmt = ergo_nipopow_v2_core::segment::BootstrapStatement {
        profile: ProfileId::V2Production128,
        tip_height: 4096,
        tip_id: whole.state_out.tip_id,
        tip_timestamp: whole.state_out.tip_timestamp,
        total_work: whole.state_out.total_work,
        mmr_root: whole.state_out.mmr_root().unwrap(),
        bootstrap_height: 3000,
        bootstrap_id: [0u8; 32],
        bootstrap_timestamp: 0,
        bootstrap_difficulty: 0,
        bootstrap_eip37_anchors: Vec::new(),
        bootstrap_modern_bands: Vec::new(),
        following_work_f: w / 2,
        w_b: cum[2999],
        a_b: 0,
        t1: w,
        t2: w,
        u_global: whole.state_out.u_global,
        sampled_required_work: 0,
        sampled_eligible: true,
    };

    // Dual-proof envelope jointly bound as pi_s BEFORE deriving audit coordinates!
    let dual = DualStructuralProof {
        zisk_proof: b"zisk-v14-stir-128bit-proof".to_vec(),
        openvm_proof: b"openvm-v21-swirl-whir-proof".to_vec(),
    };
    let pi_bytes = dual.encode_canonical().unwrap();
    let decoded = DualStructuralProof::decode_canonical(&pi_bytes).unwrap();
    assert_eq!(decoded, dual);

    let x_bytes = b"canonical-x-128";
    let bundle = build_audit_bundle(&stmt, x_bytes, &pi_bytes, &store, &raws, &cum).unwrap();
    let total_draws = verify_audit_bundle(&stmt, x_bytes, &pi_bytes, &bundle).unwrap();
    // 2 scales (w/2 and w) * 982 draws/scale = 1,964 draws
    assert_eq!(total_draws, 2 * 982);

    // Negative: flipping 1 bit in EITHER the ZisK proof OR OpenVM proof inside pi_s fails audit!
    let mut bad_dual_zisk = dual.clone();
    bad_dual_zisk.zisk_proof[0] ^= 1;
    assert!(verify_audit_bundle(
        &stmt,
        x_bytes,
        &bad_dual_zisk.encode_canonical().unwrap(),
        &bundle
    )
    .is_err());
    let mut bad_dual_openvm = dual.clone();
    bad_dual_openvm.openvm_proof[0] ^= 1;
    assert!(verify_audit_bundle(
        &stmt,
        x_bytes,
        &bad_dual_openvm.encode_canonical().unwrap(),
        &bundle
    )
    .is_err());

    // Negative: DualStructuralProof fail-closed codec checks
    assert_eq!(
        DualStructuralProof {
            zisk_proof: Vec::new(),
            openvm_proof: vec![1],
        }
        .encode_canonical(),
        Err(DualProofError::EmptyZiskProof)
    );
    assert_eq!(
        DualStructuralProof {
            zisk_proof: vec![1],
            openvm_proof: Vec::new(),
        }
        .encode_canonical(),
        Err(DualProofError::EmptyOpenVmProof)
    );
    assert_eq!(
        DualStructuralProof::decode_canonical(&pi_bytes[..pi_bytes.len() - 1]),
        Err(DualProofError::Truncated)
    );
    let mut trailing = pi_bytes.clone();
    trailing.push(0x00);
    assert_eq!(
        DualStructuralProof::decode_canonical(&trailing),
        Err(DualProofError::TrailingBytes)
    );

    // Cross-profile isolation: a higher-work candidate under a different ProfileId MUST NOT win a V2Production128 query!
    let c_other = AdmittedCandidate {
        profile: ProfileId::V2Production,
        query_height: 100,
        certified_work: 999_999,
        header_id: [1u8; 32],
        canonical_bytes: b"other-profile",
    };
    let c128 = AdmittedCandidate {
        profile: ProfileId::V2Production128,
        query_height: 100,
        certified_work: 500,
        header_id: [2u8; 32],
        canonical_bytes: b"prod128",
    };
    let cands_128 = [c_other, c128];
    assert!(select_best(ProfileId::V2Production128, 100, &cands_128[..1]).is_none());
    let winner = select_best(ProfileId::V2Production128, 100, &cands_128).unwrap();
    assert_eq!(winner.header_id, [2u8; 32]);
}
