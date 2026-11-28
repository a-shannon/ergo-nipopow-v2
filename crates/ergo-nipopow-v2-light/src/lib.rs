//! Minimal standalone Ergo NiPoPoW V2 light-client verifier (native CPU + `wasm32`).
//!
//! Deliberately carries **zero** prover SDK, **zero** CUDA, and **zero** C/C++
//! dependencies so wallets, browsers, and auditors can verify strict 128-bit
//! ZisK STIR certificates, extend returning-client checkpoints indefinitely with
//! plain headers (~160 KiB/day), and cryptographically verify Ergo transaction
//! Merkle proofs and AVL+ UTXO state proofs against certified headers.

use std::io::Read;

use bincode::Options;
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
use ergo_nipopow_v2_core::header::{blake2b256, Header};
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

/// Hard EIP-0054 anti-DoS payload caps enforced fail-closed before allocating/deserializing.
pub const MAX_CERT_COMPRESSED_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_CERT_RAW_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TAIL_COMPRESSED_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TAIL_RAW_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EXTENSION_COMPRESSED_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EXTENSION_RAW_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 514;
pub const MAX_HEADER_CHAIN_LEN: usize = 2048;
pub const MAX_AD_PROOFS_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_JSON_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Ergo maximum allowed future header timestamp drift (+20 minutes).
pub const MAX_FUTURE_DRIFT_MS: i64 = 20 * 60 * 1000;
/// `V2Production128` common-prefix confirmation depth (`k_0 = 64`).
pub const PROD128_MIN_CONFIRMATIONS: u32 = 64;

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

/// Bounded gzip decompression (defends against gzip bombs / unbounded memory growth).
pub fn decompress_if_gzip_bounded(
    bytes: &[u8],
    max_compressed: usize,
    max_decompressed: usize,
) -> Result<Vec<u8>, LightError> {
    if bytes.len() > max_compressed {
        return Err(LightError::Decompress(format!(
            "compressed payload {} B exceeds cap {} B",
            bytes.len(),
            max_compressed
        )));
    }
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut dec = GzDecoder::new(bytes).take((max_decompressed as u64).saturating_add(1));
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(|e| LightError::Decompress(e.to_string()))?;
        if out.len() > max_decompressed {
            return Err(LightError::Decompress(format!(
                "decompressed payload exceeds cap {} B",
                max_decompressed
            )));
        }
        Ok(out)
    } else {
        if bytes.len() > max_decompressed {
            return Err(LightError::Decompress(format!(
                "raw payload {} B exceeds cap {} B",
                bytes.len(),
                max_decompressed
            )));
        }
        Ok(bytes.to_vec())
    }
}

/// Transparently decompress gzip-framed payloads (`0x1f 0x8b`) under the default extension cap.
pub fn decompress_if_gzip(bytes: &[u8]) -> Result<Vec<u8>, LightError> {
    decompress_if_gzip_bounded(bytes, MAX_EXTENSION_COMPRESSED_BYTES, MAX_EXTENSION_RAW_BYTES)
}

/// Bounded decode of a length-prefixed `.u32le` header stream (raw or gzip-compressed),
/// enforcing `1..=514` bytes per Ergo header, checked index arithmetic, and max header count.
pub fn decode_u32le_headers_bounded(
    bytes: &[u8],
    max_compressed: usize,
    max_decompressed: usize,
    max_headers: usize,
) -> Result<Vec<Vec<u8>>, LightError> {
    let raw = decompress_if_gzip_bounded(bytes, max_compressed, max_decompressed)?;
    let mut headers = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        if headers.len() >= max_headers {
            return Err(LightError::Decode(format!(
                "header count exceeds cap {max_headers}"
            )));
        }
        let len_end = pos
            .checked_add(4)
            .ok_or_else(|| LightError::Decode("u32le header offset overflow".into()))?;
        if len_end > raw.len() {
            return Err(LightError::Decode("truncated u32le header length".into()));
        }
        let len = u32::from_le_bytes(raw[pos..len_end].try_into().unwrap()) as usize;
        if len == 0 || len > MAX_HEADER_BYTES {
            return Err(LightError::Decode(format!(
                "invalid Ergo header length {len} (expected 1..={MAX_HEADER_BYTES})"
            )));
        }
        let payload_end = len_end
            .checked_add(len)
            .ok_or_else(|| LightError::Decode("u32le payload offset overflow".into()))?;
        if payload_end > raw.len() {
            return Err(LightError::Decode("truncated u32le header payload".into()));
        }
        headers.push(raw[len_end..payload_end].to_vec());
        pos = payload_end;
    }
    Ok(headers)
}

/// Decode a length-prefixed `.u32le` header stream (raw or gzip-compressed) under default extension bounds.
pub fn decode_u32le_headers(bytes: &[u8]) -> Result<Vec<Vec<u8>>, LightError> {
    decode_u32le_headers_bounded(
        bytes,
        MAX_EXTENSION_COMPRESSED_BYTES,
        MAX_EXTENSION_RAW_BYTES,
        200_000,
    )
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
///
/// NOTE: `ergo-nipopow-v2-light` verifies ONLY the 128-bit ZisK STIR structural proof
/// (zero OpenVM prover SDK). When inspecting a `DualZiskV14OpenVmV21` container,
/// `dual_openvm_half_present` is `true` while `openvm_half_verified` is always `false`;
/// verifying BOTH proofs requires `ergo-nipopow-v2-aggregator verify-cert`.
#[derive(Clone, Debug)]
pub struct VerifiedLightCertificate {
    pub profile: ProfileId,
    pub backend: StructuralBackend,
    pub verified_proof: &'static str,
    pub dual_openvm_half_present: bool,
    pub openvm_half_verified: bool,
    pub statement_sha256: [u8; 32],
    pub audit_draws: usize,
    pub tail: VerifiedTail,
}

/// Cold-verify a raw or gzip-compressed `V2Certificate` (`ZiskStirV14` or ZisK STIR half of
/// `DualZiskV14OpenVmV21`) plus its exact modern tail using zero prover SDK and zero GPU.
/// Enforces `cert.statement.profile == ProfileId::V2Production128`, EIP-0054 byte caps,
/// and strict non-trailing bincode decoding fail-closed.
pub fn verify_light_certificate(
    cert_bytes: &[u8],
    tail_u32le_bytes: &[u8],
    query_height: u32,
    expected_zisk_root_vk: &[u64; 4],
) -> Result<VerifiedLightCertificate, LightError> {
    let cert_raw =
        decompress_if_gzip_bounded(cert_bytes, MAX_CERT_COMPRESSED_BYTES, MAX_CERT_RAW_BYTES)?;
    let cert: V2Certificate = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_CERT_RAW_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&cert_raw)
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

    let (dual_openvm_half_present, verified_proof) = match cert.backend {
        StructuralBackend::ZiskStirV14 => {
            verify_zisk_root_proof_bytes(&cert.structural_proof, expected_zisk_root_vk, &expected_pv)?;
            (false, "ZiskStirV14")
        }
        StructuralBackend::DualZiskV14OpenVmV21 => {
            if cert.structural_proof.len() > MAX_CERT_RAW_BYTES {
                return Err(LightError::Decode("dual structural proof exceeds cap".into()));
            }
            let dual = DualStructuralProof::decode_canonical(&cert.structural_proof)
                .map_err(|e| LightError::Decode(format!("DualStructuralProof: {e:?}")))?;
            verify_zisk_root_proof_bytes(&dual.zisk_proof, expected_zisk_root_vk, &expected_pv)?;
            (true, "ZiskStirV14_only (OpenVM half unverified in light verifier)")
        }
        StructuralBackend::OpenVmSwirlV21 => {
            return Err(LightError::UnsupportedBackend(
                "OpenVmSwirlV21 standalone requires host-aggregator; light verifier checks ZiskStirV14 and the ZisK half of DualZiskV14OpenVmV21",
            ));
        }
    };

    let audit_draws = verify_audit_bundle(&cert.statement, &x_bytes, &cert.structural_proof, &cert.audit)
        .map_err(|e| LightError::Audit(format!("{e:?}")))?;

    let expected_tail_len = cert
        .statement
        .tip_height
        .checked_sub(cert.statement.bootstrap_height)
        .ok_or_else(|| LightError::Tail("tip_height < bootstrap_height".into()))?
        as usize;
    let raw_headers = decode_u32le_headers_bounded(
        tail_u32le_bytes,
        MAX_TAIL_COMPRESSED_BYTES,
        MAX_TAIL_RAW_BYTES,
        expected_tail_len.max(16_384),
    )?;
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
        verified_proof,
        dual_openvm_half_present,
        openvm_half_verified: false,
        statement_sha256: expected_pv,
        audit_draws,
        tail,
    })
}

/// Extend a previously verified `V2Production128` `LightCheckpoint` with plain raw Ergo headers
/// (~160 KiB/day, zero STARK download). Enforces `V2Production128` profile admission, bounded
/// decoding, and optional future-timestamp drift (`<= now_ms + 20 min`, Ergo consensus clock rule).
///
/// Note: Newly appended headers within `k_0 = 64` blocks of the resulting tip are unconfirmed;
/// downstream block/state consumers MUST check confirmation depth before treating a block as final.
pub fn extend_light_checkpoint_bytes_at_time(
    checkpoint: &LightCheckpoint,
    new_headers_u32le: &[u8],
    now_ms: Option<i64>,
) -> Result<(LightCheckpoint, Vec<CertifiedHeaderSummary>), LightError> {
    if checkpoint.bootstrap.profile != ProfileId::V2Production128 {
        return Err(LightError::UnsupportedProfile(checkpoint.bootstrap.profile));
    }
    let headers = decode_u32le_headers_bounded(
        new_headers_u32le,
        MAX_EXTENSION_COMPRESSED_BYTES,
        MAX_EXTENSION_RAW_BYTES,
        200_000,
    )?;
    let (next, appended) =
        extend_checkpoint(checkpoint, &headers).map_err(|e| LightError::Tail(format!("{e:?}")))?;
    if let Some(now) = now_ms {
        let max_ts = now.saturating_add(MAX_FUTURE_DRIFT_MS);
        for h in &appended {
            if h.timestamp > max_ts {
                return Err(LightError::Tail(format!(
                    "header {} timestamp {} exceeds max allowed future drift {} (now {} + 20 min)",
                    h.height, h.timestamp, max_ts, now
                )));
            }
        }
    }
    Ok((next, appended))
}

/// Extend a previously verified `V2Production128` `LightCheckpoint` without a wall-clock check
/// (for deterministic offline replay/tests; live callers should prefer `extend_light_checkpoint_bytes_at_time`).
pub fn extend_light_checkpoint_bytes(
    checkpoint: &LightCheckpoint,
    new_headers_u32le: &[u8],
) -> Result<(LightCheckpoint, Vec<CertifiedHeaderSummary>), LightError> {
    extend_light_checkpoint_bytes_at_time(checkpoint, new_headers_u32le, None)
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
    verify_block_ad_proofs_with_lookups(
        prev_header,
        curr_header,
        ad_proofs_bytes,
        &[],
        spent_box_ids,
        created_boxes,
    )
}

/// Consensus-exact Ergo AVL+ `ADProofs` verifier matching `ErgoState.stateChanges` /
/// `StateChanges.operations` (`toLookup ++ toRemove ++ toAppend`), supporting full
/// multi-transaction blocks with `dataInputs` lookups and intra-block spend cancellation.
pub fn verify_block_ad_proofs_with_lookups(
    prev_header: &CertifiedHeaderSummary,
    curr_header: &CertifiedHeaderSummary,
    ad_proofs_bytes: &[u8],
    lookup_box_ids: &[[u8; 32]],
    spent_box_ids: &[[u8; 32]],
    created_boxes: &[([u8; 32], Vec<u8>)],
) -> Result<[u8; 33], LightError> {
    if curr_header.height != prev_header.height.saturating_add(1)
        || curr_header.parent_id != prev_header.id
    {
        return Err(LightError::AvlProof(
            "curr_header is not direct child of prev_header".into(),
        ));
    }
    if ad_proofs_bytes.len() > MAX_AD_PROOFS_BYTES {
        return Err(LightError::AvlProof(format!(
            "adProofs {} B exceeds cap {} B",
            ad_proofs_bytes.len(),
            MAX_AD_PROOFS_BYTES
        )));
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
    let total_ops = lookup_box_ids
        .len()
        .checked_add(spent_box_ids.len())
        .and_then(|v| v.checked_add(created_boxes.len()))
        .ok_or_else(|| LightError::AvlProof("operation count overflow".into()))?;
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

    for data_input in lookup_box_ids {
        let found = verifier
            .perform_one_operation(&Operation::Lookup(Bytes::copy_from_slice(data_input)))
            .map_err(|e| LightError::AvlProof(format!("AVL Lookup failed: {e}")))?;
        if found.is_none() {
            return Err(LightError::AvlProof(format!(
                "AVL Lookup returned None (proof of non-existence) for claimed dataInput {}",
                hex::encode(data_input)
            )));
        }
    }
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

/// Verified state-root transition & optional transaction Merkle inclusion result for a block
/// `H <= checkpoint.tip_height`.
///
/// NOTE: Verifies the authenticated AVL+ UTXO state-root transition (`prev_state_root -> next_state_root`)
/// and optional requested transaction Merkle inclusion (`verified_tx_id`); does NOT execute ErgoScript.
/// Callers requiring finalized depth MUST enforce `confirmations >= PROD128_MIN_CONFIRMATIONS` (`64`).
#[derive(Clone, Debug)]
pub struct VerifiedCheckpointBlockState {
    pub height: u32,
    pub block_id: [u8; 32],
    pub confirmations: u32,
    pub confirmed_k0: bool,
    pub prev_state_root: [u8; 33],
    pub next_state_root: [u8; 33],
    pub header_chain_len: usize,
    pub ad_bytes: usize,
    pub lookup_count: usize,
    pub spent_count: usize,
    pub created_count: usize,
    pub tx_merkle_verified: bool,
    pub verified_tx_id: Option<[u8; 32]>,
}

/// Trustlessly verify a block's authenticated AVL+ state transition and optional requested
/// transaction Merkle inclusion against a verified `V2Production128` `LightCheckpoint`,
/// using a descending raw Scorex header chain `[tip_height, tip_height - 1, ..., H, H - 1]`
/// bound via `BLAKE2b-256` parent hashes back from `checkpoint.tip_id`.
///
/// Enforces:
/// - `checkpoint.bootstrap.profile == ProfileId::V2Production128`,
/// - `confirmations = checkpoint.tip_height - H >= min_confirmations` (pass `PROD128_MIN_CONFIRMATIONS = 64`
///   for strict confirmation depth; `0` only for explicit unconfirmed-tip inspection),
/// - if `expected_tx_id` is `Some(txid)`, `tx_proof` MUST be present and `tx_proof.leaf_data == txid`.
#[allow(clippy::too_many_arguments)]
pub fn verify_checkpoint_block_state(
    checkpoint: &LightCheckpoint,
    header_chain_desc_u32le: &[u8],
    ad_proofs_bytes: &[u8],
    lookup_box_ids: &[[u8; 32]],
    spent_box_ids: &[[u8; 32]],
    created_boxes: &[([u8; 32], Vec<u8>)],
    tx_proof: Option<&ErgoTxMerkleProof>,
    expected_tx_id: Option<[u8; 32]>,
    min_confirmations: u32,
) -> Result<VerifiedCheckpointBlockState, LightError> {
    if checkpoint.bootstrap.profile != ProfileId::V2Production128 {
        return Err(LightError::UnsupportedProfile(checkpoint.bootstrap.profile));
    }
    let raw_headers = decode_u32le_headers_bounded(
        header_chain_desc_u32le,
        MAX_TAIL_COMPRESSED_BYTES,
        MAX_TAIL_RAW_BYTES,
        MAX_HEADER_CHAIN_LEN,
    )?;
    if raw_headers.len() < 2 {
        return Err(LightError::Tail(
            "header_chain_desc must contain at least 2 headers ([tip, tip-1])".into(),
        ));
    }

    let mut summaries: Vec<CertifiedHeaderSummary> = Vec::with_capacity(raw_headers.len());
    for (idx, raw) in raw_headers.iter().enumerate() {
        let expected_id = if idx == 0 {
            checkpoint.tip_id
        } else {
            summaries[idx - 1].parent_id
        };
        let (parsed, _) = Header::decode_native(raw, Some(&expected_id))
            .map_err(|e| LightError::Tail(format!("header[{idx}] decode/id check failed: {e:?}")))?;
        let id = expected_id;
        if idx == 0 {
            if parsed.height != checkpoint.tip_height {
                return Err(LightError::Tail(format!(
                    "header[0] height {} does not match certified checkpoint tip {}",
                    parsed.height, checkpoint.tip_height
                )));
            }
        } else {
            let child: &CertifiedHeaderSummary = &summaries[idx - 1];
            if parsed.height.saturating_add(1) != child.height {
                return Err(LightError::Tail(format!(
                    "header[{idx}] height {} does not precede child height {}",
                    parsed.height, child.height
                )));
            }
        }
        summaries.push(CertifiedHeaderSummary::from_header(&parsed, id));
    }

    let n = summaries.len();
    let curr_hdr = &summaries[n - 2];
    let prev_hdr = &summaries[n - 1];
    let confirmations = checkpoint.tip_height.saturating_sub(curr_hdr.height);
    if confirmations < min_confirmations {
        return Err(LightError::Tail(format!(
            "block {} has only {} confirmations below tip {} (required >= {}; pass allow_unconfirmed only for unconfirmed inspection)",
            curr_hdr.height, confirmations, checkpoint.tip_height, min_confirmations
        )));
    }

    let next_state_root = verify_block_ad_proofs_with_lookups(
        prev_hdr,
        curr_hdr,
        ad_proofs_bytes,
        lookup_box_ids,
        spent_box_ids,
        created_boxes,
    )?;

    let (tx_merkle_verified, verified_tx_id) = match (tx_proof, expected_tx_id) {
        (Some(proof), Some(exp)) => {
            if proof.leaf_data != exp {
                return Err(LightError::StateProof(format!(
                    "merkle proof leafData {} does not match requested txId {}",
                    hex::encode(proof.leaf_data),
                    hex::encode(exp)
                )));
            }
            verify_tx_inclusion(curr_hdr, proof)?;
            (true, Some(proof.leaf_data))
        }
        (None, Some(exp)) => {
            return Err(LightError::StateProof(format!(
                "requested txId {} but no Merkle proof was supplied",
                hex::encode(exp)
            )));
        }
        (Some(proof), None) => {
            verify_tx_inclusion(curr_hdr, proof)?;
            (true, Some(proof.leaf_data))
        }
        (None, None) => (false, None),
    };

    Ok(VerifiedCheckpointBlockState {
        height: curr_hdr.height,
        block_id: curr_hdr.id,
        confirmations,
        confirmed_k0: confirmations >= PROD128_MIN_CONFIRMATIONS,
        prev_state_root: prev_hdr.state_root,
        next_state_root,
        header_chain_len: n,
        ad_bytes: ad_proofs_bytes.len(),
        lookup_count: lookup_box_ids.len(),
        spent_count: spent_box_ids.len(),
        created_count: created_boxes.len(),
        tx_merkle_verified,
        verified_tx_id,
    })
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
/// `V2Production128` chain via `select_best` (breaking equal-work ties on the immutable
/// 32-byte `query_header_id` chain commitment rather than malleable proof container bytes).
pub fn compare_peer_certificates(
    candidates: &[(&str, &[u8], &[u8])],
    query_height: u32,
    expected_zisk_root_vk: &[u64; 4],
) -> Result<PeerComparisonResult, LightError> {
    let mut verified_items: Vec<(usize, String, VerifiedLightCertificate)> = Vec::new();
    let mut rejected_peers: Vec<(String, String)> = Vec::new();

    for (idx, (label, cert_bytes, tail_bytes)) in candidates.iter().enumerate() {
        match verify_light_certificate(cert_bytes, tail_bytes, query_height, expected_zisk_root_vk)
        {
            Ok(v) => {
                verified_items.push((idx, (*label).to_string(), v));
            }
            Err(e) => {
                rejected_peers.push(((*label).to_string(), e.to_string()));
            }
        }
    }

    let admitted: Vec<AdmittedCandidate<'_>> = verified_items
        .iter()
        .map(|(_, _, v)| AdmittedCandidate {
            profile: v.tail.checkpoint.bootstrap.profile,
            query_height: v.tail.query_height,
            certified_work: v.tail.total_work,
            header_id: v.tail.query_header_id,
            // Tie-break strictly on the chain commitment (query_header_id), never on malleable
            // proof bytes / seed trailers (defends against equal-work proof-byte grinding).
            canonical_bytes: v.tail.query_header_id.as_slice(),
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
    let (winner_index, winner_label, winner_v) = &verified_items[pos];

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

    #[test]
    fn checkpoint_block_state_verifies_and_rejects_tampered_chain() {
        let ckpt_1827840: LightCheckpoint =
            serde_json::from_str(include_str!("../testdata/checkpoint_1827840.json")).unwrap();
        let ext_bytes: &[u8] = include_bytes!("../testdata/extension_1827841_1827976.u32le");
        let (ckpt_1827976, _hdrs) = extend_light_checkpoint_bytes(&ckpt_1827840, ext_bytes).unwrap();
        assert_eq!(ckpt_1827976.tip_height, 1_827_976);

        // Extract descending 2-header chain [1827976, 1827975] from extension_1827841_1827976.u32le
        let raw_hdrs = decode_u32le_headers(ext_bytes).unwrap();
        let h_1827976 = &raw_hdrs[raw_hdrs.len() - 1];
        let h_1827975 = &raw_hdrs[raw_hdrs.len() - 2];
        let mut chain_desc = Vec::new();
        chain_desc.extend_from_slice(&(h_1827976.len() as u32).to_le_bytes());
        chain_desc.extend_from_slice(h_1827976);
        chain_desc.extend_from_slice(&(h_1827975.len() as u32).to_le_bytes());
        chain_desc.extend_from_slice(h_1827975);

        let fix: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/mainnet_1827976_live_state_proof.json"
        ))
        .unwrap();
        let ad_bytes = hex::decode(fix["ad_proofs_hex"].as_str().unwrap()).unwrap();
        let spent: Vec<[u8; 32]> = fix["spent_box_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap())
            .collect();
        let created: Vec<([u8; 32], Vec<u8>)> = fix["created_boxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let id: [u8; 32] = hex::decode(v["box_id"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let raw = hex::decode(v["raw_bytes_hex"].as_str().unwrap()).unwrap();
                (id, raw)
            })
            .collect();
        let mp = &fix["merkle_tx_proof"];
        let tx_proof = ErgoTxMerkleProof {
            leaf_data: hex::decode(mp["leafData"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            levels: mp["levels"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    let h: [u8; 32] = hex::decode(pair[0].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                    let s = pair[1].as_u64().unwrap() as u8;
                    (h, s)
                })
                .collect(),
        };

        let ok = verify_checkpoint_block_state(
            &ckpt_1827976,
            &chain_desc,
            &ad_bytes,
            &[],
            &spent,
            &created,
            Some(&tx_proof),
            Some(tx_proof.leaf_data),
            0, // explicit unconfirmed tip check
        )
        .expect("genuine checkpoint block state must verify");
        assert_eq!(ok.height, 1_827_976);
        assert_eq!(ok.confirmations, 0);
        assert!(!ok.confirmed_k0);
        assert_eq!(ok.header_chain_len, 2);
        assert!(ok.tx_merkle_verified);
        assert_eq!(ok.verified_tx_id, Some(tx_proof.leaf_data));

        // Default strict k_0 = 64 confirmations MUST reject 0-confirmation tip!
        assert!(verify_checkpoint_block_state(
            &ckpt_1827976,
            &chain_desc,
            &ad_bytes,
            &[],
            &spent,
            &created,
            Some(&tx_proof),
            Some(tx_proof.leaf_data),
            PROD128_MIN_CONFIRMATIONS,
        )
        .is_err());

        // Requested txId mismatch -> MUST reject fail-closed (GPT-6.2 H2)!
        let mut wrong_tx_id = tx_proof.leaf_data;
        wrong_tx_id[0] ^= 0x01;
        assert!(verify_checkpoint_block_state(
            &ckpt_1827976,
            &chain_desc,
            &ad_bytes,
            &[],
            &spent,
            &created,
            Some(&tx_proof),
            Some(wrong_tx_id),
            0,
        )
        .is_err());

        // Tamper 1 bit in header[0] -> must reject because BLAKE2b(header[0]) != ckpt.tip_id
        let mut bad_chain = chain_desc.clone();
        bad_chain[10] ^= 0x01;
        assert!(verify_checkpoint_block_state(
            &ckpt_1827976,
            &bad_chain,
            &ad_bytes,
            &[],
            &spent,
            &created,
            Some(&tx_proof),
            Some(tx_proof.leaf_data),
            0,
        )
        .is_err());

        // Downgraded profile checkpoint -> must reject fail-closed in BOTH block check & extend_tail!
        let mut bad_ckpt = ckpt_1827976.clone();
        bad_ckpt.bootstrap.profile = ProfileId::V2Production;
        assert!(matches!(
            verify_checkpoint_block_state(
                &bad_ckpt,
                &chain_desc,
                &ad_bytes,
                &[],
                &spent,
                &created,
                Some(&tx_proof),
                Some(tx_proof.leaf_data),
                0,
            ),
            Err(LightError::UnsupportedProfile(ProfileId::V2Production))
        ));
        let mut bad_base_ckpt = ckpt_1827840.clone();
        bad_base_ckpt.bootstrap.profile = ProfileId::V2Production;
        assert!(matches!(
            extend_light_checkpoint_bytes(&bad_base_ckpt, ext_bytes),
            Err(LightError::UnsupportedProfile(ProfileId::V2Production))
        ));

        // Future timestamp drift (> now + 20 min) MUST reject fail-closed (Claude H1)!
        assert!(extend_light_checkpoint_bytes_at_time(&ckpt_1827840, ext_bytes, Some(1_000)).is_err());
    }

    #[test]
    fn bounded_gzip_and_u32le_reject_bombs_and_oversized_headers() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        // Compress 64 KiB of zeros -> tiny gzip (~100 B), must fail against 1 KiB decompressed cap
        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&vec![0u8; 65_536]).unwrap();
        let gz = enc.finish().unwrap();
        assert!(gz.len() < 1024);
        assert!(decompress_if_gzip_bounded(&gz, 4096, 1024).is_err());

        // Oversized header (> 514 B) in u32le frame must fail before allocating
        let mut bad_u32le = Vec::new();
        bad_u32le.extend_from_slice(&(600u32).to_le_bytes());
        bad_u32le.extend_from_slice(&vec![0u8; 600]);
        assert!(decode_u32le_headers(&bad_u32le).is_err());
    }
}
