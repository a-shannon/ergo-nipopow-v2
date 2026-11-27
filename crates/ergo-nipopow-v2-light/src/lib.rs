//! Minimal standalone Ergo NiPoPoW V2 light-client verifier (native CPU + `wasm32`).
//!
//! Deliberately carries **zero** prover SDK, **zero** CUDA, and **zero** C/C++
//! dependencies so wallets, browsers, and auditors can verify strict 128-bit
//! ZisK STIR certificates, extend returning-client checkpoints indefinitely with
//! plain headers (~160 KiB/day), and cryptographically verify Ergo transaction
//! Merkle proofs and AVL+ UTXO state proofs against certified headers.

use std::io::Read;

use bytes::Bytes;
use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_verifier::BatchAVLVerifier;
use ergo_avltree_rust::batch_node::AVLTree;
use ergo_avltree_rust::operation::{KeyValue, Operation};
use ergo_nipopow_v2_core::audit::verify_audit_bundle;
use ergo_nipopow_v2_core::certificate::{
    select_best, AdmittedCandidate, DualStructuralProof, StructuralBackend, V2Certificate,
    CERT_MAGIC,
};
use ergo_nipopow_v2_core::header::blake2b256;
use ergo_nipopow_v2_core::mmr::sha256_bytes;
use ergo_nipopow_v2_core::profile::ProfileId;
use ergo_nipopow_v2_core::state_proof::ErgoTxMerkleProof;
use ergo_nipopow_v2_core::tail::{
    extend_checkpoint, verify_exact_tail, CertifiedHeaderSummary, LightCheckpoint, VerifiedTail,
};
use flate2::read::GzDecoder;
use zisk_verifier::keys::{VADCOP_FINAL_COMPRESSED_VK_BLAKE3, VADCOP_FINAL_VK_BLAKE3};

#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// Official pinned ZisK v1.4.0-alpha `agg-root` ROM root for `V2Production128` (`--remap-path-prefix` deterministic build).
pub const PINNED_ZISK_ROOT_VK_PROD128: [u64; 4] = [
    11772000642296811191,
    2917608110684279903,
    7269122849900466967,
    12697094355253129467,
];

#[derive(Debug)]
pub enum LightError {
    InvalidMagic,
    UnsupportedProfile(ProfileId),
    UnsupportedBackend(&'static str),
    Decompress(String),
    Decode(String),
    ZiskVerify(String),
    Audit(String),
    Tail(String),
    StateProof(String),
    AvlProof(String),
}

impl std::fmt::Display for LightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid V2Certificate magic"),
            Self::UnsupportedProfile(p) => write!(
                f,
                "unsupported profile {:?}: production light verifier requires V2Production128",
                p
            ),
            Self::UnsupportedBackend(msg) => write!(f, "unsupported backend: {msg}"),
            Self::Decompress(e) => write!(f, "gzip decompression failed: {e}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::ZiskVerify(e) => write!(f, "ZisK 128-bit STARK verify failed: {e}"),
            Self::Audit(e) => write!(f, "128-bit PoW audit verify failed: {e}"),
            Self::Tail(e) => write!(f, "exact tail verify failed: {e}"),
            Self::StateProof(e) => write!(f, "tx Merkle proof verify failed: {e}"),
            Self::AvlProof(e) => write!(f, "AVL+ UTXO state proof verify failed: {e}"),
        }
    }
}

impl std::error::Error for LightError {}

/// Transparently decompress gzip-framed payloads (`0x1f 0x8b`) or return raw bytes unchanged.
pub fn decompress_if_gzip(bytes: &[u8]) -> Result<Vec<u8>, LightError> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut dec = GzDecoder::new(bytes);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(|e| LightError::Decompress(e.to_string()))?;
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

/// Decode a length-prefixed `.u32le` header stream (raw or gzip-compressed).
pub fn decode_u32le_headers(bytes: &[u8]) -> Result<Vec<Vec<u8>>, LightError> {
    let raw = decompress_if_gzip(bytes)?;
    let mut headers = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        if pos + 4 > raw.len() {
            return Err(LightError::Decode("truncated u32le header length".into()));
        }
        let len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + len > raw.len() {
            return Err(LightError::Decode("truncated u32le header payload".into()));
        }
        headers.push(raw[pos..pos + len].to_vec());
        pos += len;
    }
    Ok(headers)
}

/// Parse a 4-limb comma-separated ZisK ROM root string.
pub fn parse_zisk_vk(s: &str) -> Result<[u64; 4], LightError> {
    let cleaned = s.trim().trim_start_matches('[').trim_end_matches(']');
    let limbs: Vec<u64> = cleaned
        .split(',')
        .map(|part| part.trim().parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| LightError::Decode(format!("invalid zisk VK '{s}': {e}")))?;
    if limbs.len() != 4 {
        return Err(LightError::Decode(
            "zisk VK must have exactly 4 comma-separated u64 limbs".into(),
        ));
    }
    Ok([limbs[0], limbs[1], limbs[2], limbs[3]])
}

/// Verify a ZisK v1.4.0-alpha 128-bit BLAKE3 STIR/FRI root proof against pinned setup VK,
/// pinned `agg-root` program VK, and `expected_pv = SHA-256(bincode(BootstrapStatement))`.
pub fn verify_zisk_root_proof_bytes(
    proof_bytes: &[u8],
    expected_root_vk: &[u64; 4],
    expected_pv: &[u8; 32],
) -> Result<(), LightError> {
    const SEED_TRAILER_TAG: u64 = u64::from_le_bytes(*b"ZISKSEED");
    let saved = zisk_verifier::decode_saved(proof_bytes)
        .map_err(|e| LightError::ZiskVerify(format!("decode_saved failed: {e}")))?;
    if saved.proof.hash != "blake3" {
        return Err(LightError::ZiskVerify(format!(
            "hash family must be blake3, got {}",
            saved.proof.hash
        )));
    }
    let setup_vk = if saved.proof.compressed {
        &VADCOP_FINAL_COMPRESSED_VK_BLAKE3
    } else {
        &VADCOP_FINAL_VK_BLAKE3
    };
    if proof_bytes.len() % 8 != 0 {
        return Err(LightError::ZiskVerify("proof bytes not 8-byte aligned".into()));
    }
    let mut words: Vec<u64> = proof_bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if words.last() == Some(&SEED_TRAILER_TAG) {
        if words.len() < 5 {
            return Err(LightError::ZiskVerify("truncated seed trailer".into()));
        }
        words.truncate(words.len() - 5);
    }
    let verified = zisk_verifier::verify_saved_words(&words, setup_vk, Some(expected_root_vk))
        .map_err(|e| LightError::ZiskVerify(format!("STARK verification failed: {e}")))?;
    let outs = verified
        .outputs_u32()
        .ok_or_else(|| LightError::ZiskVerify("missing u32 leaf outputs".into()))?;
    let mut committed = [0u8; 32];
    for i in 0..8 {
        committed[i * 4..(i + 1) * 4].copy_from_slice(&outs[i].to_le_bytes());
    }
    if committed.as_slice() != expected_pv.as_slice() {
        return Err(LightError::ZiskVerify(format!(
            "statement digest mismatch: got {}, expected {}",
            hex::encode(committed),
            hex::encode(expected_pv)
        )));
    }
    Ok(())
}

/// Complete light-client verification output.
#[derive(Clone, Debug)]
pub struct VerifiedLightCertificate {
    pub profile: ProfileId,
    pub backend: StructuralBackend,
    pub dual_openvm_half_present: bool,
    pub statement_sha256: [u8; 32],
    pub audit_draws: usize,
    pub tail: VerifiedTail,
}

/// Cold-verify a raw or gzip-compressed `V2Certificate` (`ZiskStirV14` or ZisK STIR half of
/// `DualZiskV14OpenVmV21`) plus its exact modern tail using zero prover SDK and zero GPU.
/// Enforces `cert.statement.profile == ProfileId::V2Production128` fail-closed.
pub fn verify_light_certificate(
    cert_bytes: &[u8],
    tail_u32le_bytes: &[u8],
    query_height: u32,
    expected_zisk_root_vk: &[u64; 4],
) -> Result<VerifiedLightCertificate, LightError> {
    let cert_raw = decompress_if_gzip(cert_bytes)?;
    let cert: V2Certificate = bincode::deserialize(&cert_raw)
        .map_err(|e| LightError::Decode(format!("certificate bincode: {e}")))?;
    if cert.magic != CERT_MAGIC {
        return Err(LightError::InvalidMagic);
    }
    if cert.statement.profile != ProfileId::V2Production128 {
        return Err(LightError::UnsupportedProfile(cert.statement.profile));
    }
    let x_bytes = bincode::serialize(&cert.statement)
        .map_err(|e| LightError::Decode(format!("statement bincode: {e}")))?;
    let expected_pv = sha256_bytes(&x_bytes);

    let dual_openvm_half_present = match cert.backend {
        StructuralBackend::ZiskStirV14 => {
            verify_zisk_root_proof_bytes(&cert.structural_proof, expected_zisk_root_vk, &expected_pv)?;
            false
        }
        StructuralBackend::DualZiskV14OpenVmV21 => {
            let dual = DualStructuralProof::decode_canonical(&cert.structural_proof)
                .map_err(|e| LightError::Decode(format!("DualStructuralProof: {e:?}")))?;
            verify_zisk_root_proof_bytes(&dual.zisk_proof, expected_zisk_root_vk, &expected_pv)?;
            true
        }
        StructuralBackend::OpenVmSwirlV21 => {
            return Err(LightError::UnsupportedBackend(
                "OpenVmSwirlV21 standalone requires host-aggregator; light verifier checks ZiskStirV14 and DualZiskV14OpenVmV21",
            ));
        }
    };

    let audit_draws = verify_audit_bundle(&cert.statement, &x_bytes, &cert.structural_proof, &cert.audit)
        .map_err(|e| LightError::Audit(format!("{e:?}")))?;

    let raw_headers = decode_u32le_headers(tail_u32le_bytes)?;
    let expected_tail_len = (cert.statement.tip_height - cert.statement.bootstrap_height) as usize;
    let tail_slice: &[Vec<u8>] = if raw_headers.len() == expected_tail_len {
        &raw_headers[..]
    } else if raw_headers.len() == cert.statement.tip_height as usize {
        &raw_headers[cert.statement.bootstrap_height as usize..]
    } else {
        return Err(LightError::Tail(format!(
            "unexpected header count {} (expected tail {} or full {})",
            raw_headers.len(),
            expected_tail_len,
            cert.statement.tip_height
        )));
    };
    let tail = verify_exact_tail(&cert.statement, tail_slice, query_height)
        .map_err(|e| LightError::Tail(format!("{e:?}")))?;

    Ok(VerifiedLightCertificate {
        profile: cert.statement.profile,
        backend: cert.backend,
        dual_openvm_half_present,
        statement_sha256: expected_pv,
        audit_draws,
        tail,
    })
}

/// Extend a previously verified `LightCheckpoint` with plain raw Ergo headers only
/// (~160 KiB/day, zero STARK download, zero prover dependency).
pub fn extend_light_checkpoint_bytes(
    checkpoint: &LightCheckpoint,
    new_headers_u32le: &[u8],
) -> Result<(LightCheckpoint, Vec<CertifiedHeaderSummary>), LightError> {
    let headers = decode_u32le_headers(new_headers_u32le)?;
    extend_checkpoint(checkpoint, &headers).map_err(|e| LightError::Tail(format!("{e:?}")))
}

/// Verify an Ergo block's authentic AVL+ `ADProofs` state-root transition from
/// `prev_header.state_root` to `curr_header.state_root`, proving that every
/// `spent_box_ids` entry existed in the authenticated UTXO set and was removed and
/// every `created_boxes` entry (with `BLAKE2b-256(raw_bytes) == box_id`) was inserted.
pub fn verify_block_ad_proofs(
    prev_header: &CertifiedHeaderSummary,
    curr_header: &CertifiedHeaderSummary,
    ad_proofs_bytes: &[u8],
    spent_box_ids: &[[u8; 32]],
    created_boxes: &[([u8; 32], Vec<u8>)],
) -> Result<[u8; 33], LightError> {
    if curr_header.height != prev_header.height + 1 || curr_header.parent_id != prev_header.id {
        return Err(LightError::AvlProof(
            "curr_header is not direct child of prev_header".into(),
        ));
    }
    let ad_root = blake2b256(ad_proofs_bytes);
    if ad_root != curr_header.ad_proofs_root {
        return Err(LightError::AvlProof(format!(
            "adProofs digest mismatch: got {}, expected {}",
            hex::encode(ad_root),
            hex::encode(curr_header.ad_proofs_root)
        )));
    }
    for (box_id, raw_bytes) in created_boxes {
        let computed = blake2b256(raw_bytes);
        if &computed != box_id {
            return Err(LightError::AvlProof(format!(
                "created boxId mismatch: blake2b(raw)={} != {}",
                hex::encode(computed),
                hex::encode(box_id)
            )));
        }
    }

    let start_digest = Bytes::copy_from_slice(&prev_header.state_root);
    let proof_buf = Bytes::copy_from_slice(ad_proofs_bytes);
    let total_ops = spent_box_ids.len() + created_boxes.len();
    fn verifier_resolver(digest: &[u8; 32]) -> ergo_avltree_rust::batch_node::Node {
        ergo_avltree_rust::batch_node::Node::LabelOnly(
            ergo_avltree_rust::batch_node::NodeHeader::new(Some(*digest), None),
        )
    }
    let tree = AVLTree::new(verifier_resolver, 32, None);
    let mut verifier = BatchAVLVerifier::new(
        &start_digest,
        &proof_buf,
        tree,
        Some(total_ops),
        Some(spent_box_ids.len()),
    )
    .map_err(|e| LightError::AvlProof(format!("reconstruct_tree failed: {e}")))?;

    for spent in spent_box_ids {
        verifier
            .perform_one_operation(&Operation::Remove(Bytes::copy_from_slice(spent)))
            .map_err(|e| LightError::AvlProof(format!("AVL Remove failed: {e}")))?;
    }
    for (box_id, raw_bytes) in created_boxes {
        verifier
            .perform_one_operation(&Operation::Insert(KeyValue {
                key: Bytes::copy_from_slice(box_id),
                value: Bytes::copy_from_slice(raw_bytes),
            }))
            .map_err(|e| LightError::AvlProof(format!("AVL Insert failed: {e}")))?;
    }

    let final_digest = verifier
        .digest()
        .ok_or_else(|| LightError::AvlProof("verifier produced empty digest".into()))?;
    if final_digest.as_ref() != curr_header.state_root.as_slice() {
        return Err(LightError::AvlProof(format!(
            "AVL+ stateRoot mismatch: computed {}, expected {}",
            hex::encode(final_digest.as_ref()),
            hex::encode(curr_header.state_root)
        )));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(final_digest.as_ref());
    Ok(out)
}

/// Verify an Ergo transaction Merkle membership proof against a certified header's `transactions_root`.
pub fn verify_tx_inclusion(
    header: &CertifiedHeaderSummary,
    proof: &ErgoTxMerkleProof,
) -> Result<(), LightError> {
    proof
        .verify_against_header(&header.transactions_root)
        .map_err(|e| LightError::StateProof(format!("{e:?}")))
}

/// Outcome of comparing multiple untrusted peer certificates for the same query height.
#[derive(Clone, Debug)]
pub struct PeerComparisonResult {
    pub winner_index: usize,
    pub winner_label: String,
    pub winner_work: u128,
    pub winner_header_id: [u8; 32],
    pub admitted_count: usize,
    pub rejected_peers: Vec<(String, String)>,
}

/// Independently verify multiple untrusted peer `(label, cert_bytes, tail_bytes)` bundles,
/// drop invalid/tampered peers fail-closed, and deterministically pick the heaviest valid
/// `V2Production128` chain via `select_best` (tie-breaking by smallest canonical bytes).
pub fn compare_peer_certificates(
    candidates: &[(&str, &[u8], &[u8])],
    query_height: u32,
    expected_zisk_root_vk: &[u64; 4],
) -> Result<PeerComparisonResult, LightError> {
    let mut verified_items: Vec<(usize, String, VerifiedLightCertificate, Vec<u8>)> = Vec::new();
    let mut rejected_peers: Vec<(String, String)> = Vec::new();

    for (idx, (label, cert_bytes, tail_bytes)) in candidates.iter().enumerate() {
        match verify_light_certificate(cert_bytes, tail_bytes, query_height, expected_zisk_root_vk)
        {
            Ok(v) => {
                let raw = decompress_if_gzip(cert_bytes)?;
                verified_items.push((idx, (*label).to_string(), v, raw));
            }
            Err(e) => {
                rejected_peers.push(((*label).to_string(), e.to_string()));
            }
        }
    }

    let admitted: Vec<AdmittedCandidate<'_>> = verified_items
        .iter()
        .map(|(_, _, v, raw)| AdmittedCandidate {
            profile: v.tail.checkpoint.bootstrap.profile,
            query_height: v.tail.query_height,
            certified_work: v.tail.total_work,
            header_id: v.tail.query_header_id,
            canonical_bytes: raw.as_slice(),
        })
        .collect();

    let best = select_best(ProfileId::V2Production128, query_height, &admitted)
        .ok_or_else(|| LightError::Decode("no valid candidate admitted".into()))?;
    let pos = admitted
        .iter()
        .position(|c| {
            c.certified_work == best.certified_work
                && c.header_id == best.header_id
                && c.canonical_bytes == best.canonical_bytes
        })
        .expect("selected candidate present");
    let (winner_index, winner_label, winner_v, _) = &verified_items[pos];

    Ok(PeerComparisonResult {
        winner_index: *winner_index,
        winner_label: winner_label.clone(),
        winner_work: winner_v.tail.total_work,
        winner_header_id: winner_v.tail.query_header_id,
        admitted_count: admitted.len(),
        rejected_peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct RawCreatedBox {
        box_id: String,
        raw_bytes_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct RawMerkleProof {
        #[serde(rename = "leafData")]
        leaf_data: String,
        levels: Vec<(String, u8)>,
    }

    #[derive(serde::Deserialize)]
    struct MainnetStateFixture {
        height: u32,
        prev_height: u32,
        header_id: String,
        prev_header_id: String,
        prev_state_root: String,
        next_state_root: String,
        ad_proofs_root: String,
        ad_proofs_hex: String,
        spent_box_ids: Vec<String>,
        created_boxes: Vec<RawCreatedBox>,
        merkle_tx_proof_1823985: RawMerkleProof,
        tx_root_1823985: String,
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn hex33(s: &str) -> [u8; 33] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn real_mainnet_1823986_avl_adproofs_and_1823985_tx_merkle_with_negatives() {
        let fix: MainnetStateFixture =
            serde_json::from_str(include_str!("../testdata/mainnet_1823986_state_proof.json"))
                .unwrap();

        let prev_hdr = CertifiedHeaderSummary {
            height: fix.prev_height,
            id: hex32(&fix.prev_header_id),
            parent_id: [0u8; 32],
            state_root: hex33(&fix.prev_state_root),
            transactions_root: hex32(&fix.tx_root_1823985),
            ad_proofs_root: [0u8; 32],
            timestamp: 0,
            n_bits: 0,
        };
        let curr_hdr = CertifiedHeaderSummary {
            height: fix.height,
            id: hex32(&fix.header_id),
            parent_id: prev_hdr.id,
            state_root: hex33(&fix.next_state_root),
            transactions_root: [0u8; 32],
            ad_proofs_root: hex32(&fix.ad_proofs_root),
            timestamp: 0,
            n_bits: 0,
        };

        let ad_bytes = hex::decode(&fix.ad_proofs_hex).unwrap();
        let spent: Vec<[u8; 32]> = fix.spent_box_ids.iter().map(|s| hex32(s)).collect();
        let created: Vec<([u8; 32], Vec<u8>)> = fix
            .created_boxes
            .iter()
            .map(|b| (hex32(&b.box_id), hex::decode(&b.raw_bytes_hex).unwrap()))
            .collect();

        // 1. Real Ergo mainnet block 1,823,986 AVL+ ADProofs replay: stateRoot(1823985) -> stateRoot(1823986)!
        let new_root =
            verify_block_ad_proofs(&prev_hdr, &curr_hdr, &ad_bytes, &spent, &created).unwrap();
        assert_eq!(new_root, curr_hdr.state_root);

        // Negative A: 1-bit flip in ADProofs bytes -> rejected fail-closed
        let mut bad_ad = ad_bytes.clone();
        bad_ad[100] ^= 0x01;
        assert!(verify_block_ad_proofs(&prev_hdr, &curr_hdr, &bad_ad, &spent, &created).is_err());

        // Negative B: 1-bit flip in created box bytes -> rejected fail-closed
        let mut bad_created = created.clone();
        bad_created[0].1[0] ^= 0x01;
        assert!(
            verify_block_ad_proofs(&prev_hdr, &curr_hdr, &ad_bytes, &spent, &bad_created).is_err()
        );

        // Negative C: wrong expected state_root -> rejected fail-closed
        let mut bad_hdr = curr_hdr.clone();
        bad_hdr.state_root[0] ^= 0x01;
        assert!(verify_block_ad_proofs(&prev_hdr, &bad_hdr, &ad_bytes, &spent, &created).is_err());

        // 2. Real Ergo mainnet block 1,823,985 Tx Merkle inclusion proof!
        let tx_proof = ErgoTxMerkleProof {
            leaf_data: hex32(&fix.merkle_tx_proof_1823985.leaf_data),
            levels: fix
                .merkle_tx_proof_1823985
                .levels
                .iter()
                .map(|(h, s)| (hex32(h), *s))
                .collect(),
        };
        verify_tx_inclusion(&prev_hdr, &tx_proof).unwrap();

        // Negative D: 1-bit flip in tx Merkle leaf -> rejected fail-closed
        let mut bad_tx = tx_proof.clone();
        bad_tx.leaf_data[31] ^= 0x01;
        assert!(verify_tx_inclusion(&prev_hdr, &bad_tx).is_err());
    }

    #[test]
    fn real_mainnet_extend_tail_1827840_to_1827976_crossing_eip37_retarget_and_negatives() {
        let ckpt: LightCheckpoint =
            serde_json::from_str(include_str!("../testdata/checkpoint_1827840.json")).unwrap();
        let ext_bytes: &[u8] = include_bytes!("../testdata/extension_1827841_1827976.u32le");

        // Positive: advance 1,827,840 -> 1,827,976 (+136 live mainnet headers, crossing real EIP-37 retarget at 1,827,969)
        let (advanced, hdrs) = extend_light_checkpoint_bytes(&ckpt, ext_bytes).unwrap();
        assert_eq!(hdrs.len(), 136);
        assert_eq!(hdrs[127].n_bits, 105_028_762);
        assert_eq!(hdrs[128].n_bits, 105_229_481);
        assert_eq!(advanced.tip_height, 1_827_976);
        assert_eq!(
            hex::encode(advanced.tip_id),
            "681165c66cb2777f9e4508c4ccb2480d69d9106a9ca26ded37384867606a6996"
        );
        assert_eq!(
            hex::encode(advanced.tip_state_root),
            "25b40830db79b785281b2e76d9d932f97594893d420b24d7336eb7c867ef954819"
        );

        // Negative A: 1-bit flip in first header parent link -> rejected fail-closed
        let mut bad_parent = ext_bytes.to_vec();
        bad_parent[20] ^= 0x01;
        assert!(extend_light_checkpoint_bytes(&ckpt, &bad_parent).is_err());

        // Negative B: 1-bit flip in Autolykos v2 PoW nonce of final header 1,827,976 -> rejected fail-closed
        let mut bad_pow = ext_bytes.to_vec();
        let last = bad_pow.len() - 1;
        bad_pow[last] ^= 0x01;
        assert!(extend_light_checkpoint_bytes(&ckpt, &bad_pow).is_err());

        // Negative C: decode, mutate nBits of retarget header 1,827,969 (index 128), re-pack -> rejected by EIP-37 DAA
        let mut headers = decode_u32le_headers(ext_bytes).unwrap();
        assert_eq!(headers.len(), 136);
        // Header 1,827,969 is index 128; mutate its nBits field (right after extension_root)
        let h128 = &mut headers[128];
        // Find canonical big-endian bytes of 105229481 (0x06459ca9) and flip 1 bit
        let target_nbits = 105_229_481u32.to_be_bytes();
        let pos = h128
            .windows(4)
            .position(|w| w == target_nbits)
            .expect("nBits bytes present in 1,827,969");
        h128[pos + 3] ^= 0x01;
        let mut bad_daa = Vec::with_capacity(ext_bytes.len());
        for h in &headers {
            bad_daa.extend_from_slice(&(h.len() as u32).to_le_bytes());
            bad_daa.extend_from_slice(h);
        }
        assert!(extend_light_checkpoint_bytes(&ckpt, &bad_daa).is_err());
    }

    #[derive(serde::Deserialize)]
    struct LiveStateFixture {
        height: u32,
        prev_height: u32,
        ad_proofs_hex: String,
        spent_box_ids: Vec<String>,
        created_boxes: Vec<RawCreatedBox>,
        merkle_tx_proof: RawMerkleProof,
    }

    #[test]
    fn real_mainnet_live_1827976_post_stark_adproofs_and_tx_merkle_with_negatives() {
        let ckpt: LightCheckpoint =
            serde_json::from_str(include_str!("../testdata/checkpoint_1827840.json")).unwrap();
        let ext_bytes: &[u8] = include_bytes!("../testdata/extension_1827841_1827976.u32le");
        let fix: LiveStateFixture = serde_json::from_str(include_str!(
            "../testdata/mainnet_1827976_live_state_proof.json"
        ))
        .unwrap();

        // 1. Advance 1,827,840 -> 1,827,976 using plain headers only (crossing real EIP-37 retarget at 1,827,969)
        let (next_ckpt, hdrs) = extend_light_checkpoint_bytes(&ckpt, ext_bytes).unwrap();
        assert_eq!(next_ckpt.tip_height, 1_827_976);
        let prev_hdr = hdrs.iter().find(|h| h.height == fix.prev_height).unwrap();
        let curr_hdr = hdrs.iter().find(|h| h.height == fix.height).unwrap();

        // 2. Replay real mainnet block 1,827,976 ADProofs (2,828 B) bit-for-bit on the live post-STARK tip!
        let ad_bytes = hex::decode(&fix.ad_proofs_hex).unwrap();
        let spent: Vec<[u8; 32]> = fix.spent_box_ids.iter().map(|s| hex32(s)).collect();
        let created: Vec<([u8; 32], Vec<u8>)> = fix
            .created_boxes
            .iter()
            .map(|b| (hex32(&b.box_id), hex::decode(&b.raw_bytes_hex).unwrap()))
            .collect();
        let new_root =
            verify_block_ad_proofs(prev_hdr, curr_hdr, &ad_bytes, &spent, &created).unwrap();
        assert_eq!(new_root, curr_hdr.state_root);
        assert_eq!(new_root, next_ckpt.tip_state_root);

        // 3. Verify real mainnet block 1,827,976 Scorex tx Merkle inclusion proof against live tip header
        let tx_proof = ErgoTxMerkleProof {
            leaf_data: hex32(&fix.merkle_tx_proof.leaf_data),
            levels: fix
                .merkle_tx_proof
                .levels
                .iter()
                .map(|(h, s)| (hex32(h), *s))
                .collect(),
        };
        verify_tx_inclusion(curr_hdr, &tx_proof).unwrap();

        // Negatives: 1-bit tampers on ADProofs, created box, and tx Merkle leaf all fail closed
        let mut bad_ad = ad_bytes.clone();
        bad_ad[42] ^= 0x01;
        assert!(verify_block_ad_proofs(prev_hdr, curr_hdr, &bad_ad, &spent, &created).is_err());

        let mut bad_created = created.clone();
        bad_created[0].1[10] ^= 0x01;
        assert!(
            verify_block_ad_proofs(prev_hdr, curr_hdr, &ad_bytes, &spent, &bad_created).is_err()
        );

        let mut bad_tx = tx_proof.clone();
        bad_tx.leaf_data[0] ^= 0x01;
        assert!(verify_tx_inclusion(curr_hdr, &bad_tx).is_err());
    }

    #[test]
    fn multi_peer_fork_selection_prefers_heaviest_valid_and_breaks_ties() {
        let a_bytes = b"candidate-b";
        let b_bytes = b"candidate-a";
        let cands = [
            AdmittedCandidate {
                profile: ProfileId::V2Production128,
                query_height: 1_823_986,
                certified_work: 100,
                header_id: [0x11; 32],
                canonical_bytes: a_bytes,
            },
            AdmittedCandidate {
                profile: ProfileId::V2Production128,
                query_height: 1_823_986,
                certified_work: 250,
                header_id: [0x22; 32],
                canonical_bytes: a_bytes,
            },
            AdmittedCandidate {
                profile: ProfileId::V2Production128,
                query_height: 1_823_986,
                certified_work: 250,
                header_id: [0x33; 32],
                canonical_bytes: b_bytes,
            },
            AdmittedCandidate {
                profile: ProfileId::V2Production, // wrong profile -> ignored!
                query_height: 1_823_986,
                certified_work: 999_999,
                header_id: [0xff; 32],
                canonical_bytes: b_bytes,
            },
        ];
        let winner = select_best(ProfileId::V2Production128, 1_823_986, &cands).unwrap();
        assert_eq!(winner.certified_work, 250);
        assert_eq!(winner.header_id, [0x33; 32]); // equal work -> lexicographically smaller canonical_bytes ("candidate-a" < "candidate-b")
    }

    #[test]
    fn downgraded_profile_certificate_is_rejected_fail_closed() {
        use ergo_nipopow_v2_core::audit::AuditBundle;
        use ergo_nipopow_v2_core::mmr::MmrMultiproof;
        use ergo_nipopow_v2_core::segment::BootstrapStatement;

        let ckpt: LightCheckpoint =
            serde_json::from_str(include_str!("../testdata/checkpoint_1827840.json")).unwrap();
        let mut downgraded_stmt: BootstrapStatement = ckpt.bootstrap.clone();
        downgraded_stmt.profile = ProfileId::V2Production;
        let cert = V2Certificate {
            magic: CERT_MAGIC,
            backend: StructuralBackend::ZiskStirV14,
            statement: downgraded_stmt,
            structural_proof: vec![0u8; 64],
            audit: AuditBundle {
                leaves: Vec::new(),
                multiproof: MmrMultiproof {
                    siblings: Vec::new(),
                    untouched_peaks: Vec::new(),
                },
            },
        };
        let cert_bytes = bincode::serialize(&cert).unwrap();
        let err = verify_light_certificate(
            &cert_bytes,
            &[],
            1_823_986,
            &PINNED_ZISK_ROOT_VK_PROD128,
        )
        .unwrap_err();
        match err {
            LightError::UnsupportedProfile(ProfileId::V2Production) => {}
            other => panic!("expected UnsupportedProfile(V2Production), got {other:?}"),
        }
    }
}
