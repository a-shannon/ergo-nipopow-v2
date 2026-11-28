//! Minimal zero-dependency `wasm32-unknown-unknown` C-ABI exports for executing
//! `ergo-nipopow-v2-light` directly inside V8 (Node.js, Chromium, Android WebView)
//! and any standard WebAssembly host without `wasm-bindgen` or npm toolchains.
//!
//! Host ABI contract:
//! - Callers allocate input buffers via `wasm_alloc(len)` (capped at `MAX_EXTENSION_RAW_BYTES`;
//!   returns `0` on overflow/oversized requests) and release them with `wasm_dealloc(ptr, len)`
//!   inside a `try / finally` block.
//! - Return code `0` indicates success; non-zero indicates fail-closed rejection.
//! - `wasm_last_output_ptr()` / `wasm_last_output_len()` point to UTF-8 JSON (on `0`) or
//!   UTF-8 error text (on non-zero) valid until the next output-producing call.

use std::cell::RefCell;

use ergo_nipopow_v2_core::state_proof::ErgoTxMerkleProof;
use ergo_nipopow_v2_core::tail::LightCheckpoint;

use crate::{
    extend_light_checkpoint_bytes_at_time, verify_block_ad_proofs_with_lookups,
    verify_checkpoint_block_state, verify_light_certificate, verify_tx_inclusion,
    MAX_EXTENSION_RAW_BYTES, MAX_JSON_INPUT_BYTES, PINNED_ZISK_ROOT_VK_PROD128,
    PROD128_MIN_CONFIRMATIONS,
};

thread_local! {
    static LAST_OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_output(bytes: Vec<u8>) {
    LAST_OUTPUT.with(|cell| {
        *cell.borrow_mut() = bytes;
    });
}

fn set_err(msg: impl AsRef<str>) -> i32 {
    set_output(msg.as_ref().as_bytes().to_vec());
    1
}

#[no_mangle]
pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
    if len > MAX_EXTENSION_RAW_BYTES {
        return core::ptr::null_mut();
    }
    let mut buf = Vec::<u8>::new();
    if buf.try_reserve_exact(len).is_err() {
        return core::ptr::null_mut();
    }
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn wasm_dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len <= MAX_EXTENSION_RAW_BYTES {
        drop(Vec::from_raw_parts(ptr, 0, len));
    }
}

#[no_mangle]
pub extern "C" fn wasm_last_output_ptr() -> *const u8 {
    LAST_OUTPUT.with(|cell| cell.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn wasm_last_output_len() -> usize {
    LAST_OUTPUT.with(|cell| cell.borrow().len())
}

unsafe fn slice_from_raw_bounded<'a>(
    ptr: *const u8,
    len: usize,
    max_len: usize,
) -> Result<&'a [u8], String> {
    if len > max_len {
        return Err(format!("input buffer {} B exceeds cap {} B", len, max_len));
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("null pointer with non-zero length".into());
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

#[derive(serde::Deserialize)]
struct WasmCreatedBox {
    box_id: String,
    raw_bytes_hex: String,
}

#[derive(serde::Deserialize)]
struct WasmMerkleProof {
    #[serde(rename = "leafData")]
    leaf_data: String,
    levels: Vec<(String, u8)>,
}

#[derive(serde::Deserialize)]
struct WasmLiveFixture {
    height: u32,
    prev_height: u32,
    ad_proofs_hex: String,
    #[serde(default)]
    lookup_box_ids: Vec<String>,
    spent_box_ids: Vec<String>,
    created_boxes: Vec<WasmCreatedBox>,
    merkle_tx_proof: WasmMerkleProof,
}

#[derive(serde::Serialize)]
struct WasmColdOutput {
    profile: String,
    backend: String,
    verified_proof: String,
    dual_openvm_present: bool,
    openvm_half_verified: bool,
    query_height: u32,
    tip_height: u32,
    query_id: String,
    query_state_root: String,
    audit_draws: usize,
    checkpoint_json: String,
}

#[derive(serde::Serialize)]
struct WasmExtendOutput {
    headers_verified: usize,
    prev_tip_height: u32,
    tip_height: u32,
    tip_id: String,
    tip_state_root: String,
    checkpoint_json: String,
}

#[derive(serde::Serialize)]
struct WasmLiveStateOutput {
    live_height: u32,
    tip_height: u32,
    prev_state_root: String,
    next_state_root: String,
    ad_bytes: usize,
    lookup_count: usize,
    spent_count: usize,
    created_count: usize,
    tx_merkle_verified: bool,
    verified_tx_id: String,
}

#[derive(serde::Deserialize)]
struct WasmCheckpointBlockInput {
    ad_proofs_hex: String,
    #[serde(default)]
    lookup_box_ids: Vec<String>,
    spent_box_ids: Vec<String>,
    created_boxes: Vec<WasmCreatedBox>,
    merkle_tx_proof: Option<WasmMerkleProof>,
    #[serde(default)]
    expected_tx_id: Option<String>,
    #[serde(default)]
    min_confirmations: Option<u32>,
}

#[derive(serde::Serialize)]
struct WasmCheckpointBlockOutput {
    height: u32,
    block_id: String,
    tip_height: u32,
    confirmations: u32,
    confirmed_k0: bool,
    header_chain_len: usize,
    prev_state_root: String,
    next_state_root: String,
    ad_bytes: usize,
    lookup_count: usize,
    spent_count: usize,
    created_count: usize,
    tx_merkle_verified: bool,
    verified_tx_id: Option<String>,
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32-byte hex".to_string())
}

/// Cold-verify a raw or gzip-compressed `V2Production128` certificate + exact tail inside WASM.
/// Verifies the 128-bit ZisK STIR half only (`openvm_half_verified: false`).
#[no_mangle]
pub unsafe extern "C" fn wasm_verify_light_cert(
    cert_ptr: *const u8,
    cert_len: usize,
    tail_ptr: *const u8,
    tail_len: usize,
    query_height: u32,
    vk_ptr: *const u8,
    vk_len: usize,
) -> i32 {
    let cert_bytes = match slice_from_raw_bounded(cert_ptr, cert_len, MAX_EXTENSION_RAW_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let tail_bytes = match slice_from_raw_bounded(tail_ptr, tail_len, MAX_EXTENSION_RAW_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let vk = if vk_len == 0 {
        PINNED_ZISK_ROOT_VK_PROD128
    } else if vk_len == 32 {
        let b = match slice_from_raw_bounded(vk_ptr, vk_len, 32) {
            Ok(v) => v,
            Err(e) => return set_err(e),
        };
        [
            u64::from_le_bytes(b[0..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..16].try_into().unwrap()),
            u64::from_le_bytes(b[16..24].try_into().unwrap()),
            u64::from_le_bytes(b[24..32].try_into().unwrap()),
        ]
    } else {
        return set_err("vk_len must be 0 or 32 bytes");
    };

    let res = match verify_light_certificate(cert_bytes, tail_bytes, query_height, &vk) {
        Ok(v) => v,
        Err(e) => return set_err(e.to_string()),
    };
    let qh = match res.tail.query_header.as_ref() {
        Some(h) => h,
        None => return set_err("missing query header summary"),
    };
    let checkpoint_json = match serde_json::to_string(&res.tail.checkpoint) {
        Ok(s) => s,
        Err(e) => return set_err(e.to_string()),
    };
    let out = WasmColdOutput {
        profile: format!("{:?}", res.profile),
        backend: format!("{:?}", res.backend),
        verified_proof: res.verified_proof.to_string(),
        dual_openvm_present: res.dual_openvm_half_present,
        openvm_half_verified: res.openvm_half_verified,
        query_height: res.tail.query_height,
        tip_height: res.tail.tip_height,
        query_id: hex::encode(res.tail.query_header_id),
        query_state_root: hex::encode(qh.state_root),
        audit_draws: res.audit_draws,
        checkpoint_json,
    };
    match serde_json::to_vec(&out) {
        Ok(v) => {
            set_output(v);
            0
        }
        Err(e) => set_err(e.to_string()),
    }
}

/// Extend a JSON `LightCheckpoint` with plain raw/gzip Ergo headers (zero STARK),
/// enforcing strict `V2Production128` profile admission and optional future timestamp drift
/// (`<= now_ms + 20 min` when `now_ms > 0`).
#[no_mangle]
pub unsafe extern "C" fn wasm_extend_tail_at_time(
    ckpt_ptr: *const u8,
    ckpt_len: usize,
    ext_ptr: *const u8,
    ext_len: usize,
    now_ms: i64,
) -> i32 {
    let ckpt_bytes = match slice_from_raw_bounded(ckpt_ptr, ckpt_len, MAX_JSON_INPUT_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let ext_bytes = match slice_from_raw_bounded(ext_ptr, ext_len, MAX_EXTENSION_RAW_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let ckpt: LightCheckpoint = match serde_json::from_slice(ckpt_bytes) {
        Ok(c) => c,
        Err(e) => return set_err(format!("checkpoint json: {e}")),
    };
    let clock = if now_ms > 0 { Some(now_ms) } else { None };
    let (next, hdrs) = match extend_light_checkpoint_bytes_at_time(&ckpt, ext_bytes, clock) {
        Ok(v) => v,
        Err(e) => return set_err(e.to_string()),
    };
    let checkpoint_json = match serde_json::to_string(&next) {
        Ok(s) => s,
        Err(e) => return set_err(e.to_string()),
    };
    let out = WasmExtendOutput {
        headers_verified: hdrs.len(),
        prev_tip_height: ckpt.tip_height,
        tip_height: next.tip_height,
        tip_id: hex::encode(next.tip_id),
        tip_state_root: hex::encode(next.tip_state_root),
        checkpoint_json,
    };
    match serde_json::to_vec(&out) {
        Ok(v) => {
            set_output(v);
            0
        }
        Err(e) => set_err(e.to_string()),
    }
}

/// Extend a JSON `LightCheckpoint` with plain raw/gzip Ergo headers (zero STARK, no wall-clock check).
/// Still enforces strict `V2Production128` profile admission fail-closed.
#[no_mangle]
pub unsafe extern "C" fn wasm_extend_tail(
    ckpt_ptr: *const u8,
    ckpt_len: usize,
    ext_ptr: *const u8,
    ext_len: usize,
) -> i32 {
    wasm_extend_tail_at_time(ckpt_ptr, ckpt_len, ext_ptr, ext_len, 0)
}

/// End-to-end post-STARK state proof verification inside WASM:
/// extends `V2Production128` `LightCheckpoint` with plain headers, locates `prev_height` & `height`,
/// verifies real Ergo AVL+ `ADProofs` state transition and Scorex Tx Merkle proof.
#[no_mangle]
pub unsafe extern "C" fn wasm_verify_live_state_proof(
    ckpt_ptr: *const u8,
    ckpt_len: usize,
    ext_ptr: *const u8,
    ext_len: usize,
    fix_ptr: *const u8,
    fix_len: usize,
) -> i32 {
    let ckpt_bytes = match slice_from_raw_bounded(ckpt_ptr, ckpt_len, MAX_JSON_INPUT_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let ext_bytes = match slice_from_raw_bounded(ext_ptr, ext_len, MAX_EXTENSION_RAW_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let fix_bytes = match slice_from_raw_bounded(fix_ptr, fix_len, MAX_JSON_INPUT_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };

    let ckpt: LightCheckpoint = match serde_json::from_slice(ckpt_bytes) {
        Ok(c) => c,
        Err(e) => return set_err(format!("checkpoint json: {e}")),
    };
    let fix: WasmLiveFixture = match serde_json::from_slice(fix_bytes) {
        Ok(f) => f,
        Err(e) => return set_err(format!("fixture json: {e}")),
    };
    let (next, hdrs) = match extend_light_checkpoint_bytes_at_time(&ckpt, ext_bytes, None) {
        Ok(v) => v,
        Err(e) => return set_err(e.to_string()),
    };

    let prev_hdr = match hdrs.iter().find(|h| h.height == fix.prev_height) {
        Some(h) => h,
        None => return set_err(format!("prev_height {} not found in extension", fix.prev_height)),
    };
    let curr_hdr = match hdrs.iter().find(|h| h.height == fix.height) {
        Some(h) => h,
        None => return set_err(format!("height {} not found in extension", fix.height)),
    };

    let ad_bytes = match hex::decode(&fix.ad_proofs_hex) {
        Ok(b) => b,
        Err(e) => return set_err(format!("ad_proofs_hex: {e}")),
    };
    let mut lookups = Vec::with_capacity(fix.lookup_box_ids.len());
    for s in &fix.lookup_box_ids {
        match hex32(s) {
            Ok(id) => lookups.push(id),
            Err(e) => return set_err(e),
        }
    }
    let mut spent = Vec::with_capacity(fix.spent_box_ids.len());
    for s in &fix.spent_box_ids {
        match hex32(s) {
            Ok(id) => spent.push(id),
            Err(e) => return set_err(e),
        }
    }
    let mut created = Vec::with_capacity(fix.created_boxes.len());
    for b in &fix.created_boxes {
        let id = match hex32(&b.box_id) {
            Ok(v) => v,
            Err(e) => return set_err(e),
        };
        let raw = match hex::decode(&b.raw_bytes_hex) {
            Ok(v) => v,
            Err(e) => return set_err(e.to_string()),
        };
        created.push((id, raw));
    }

    let new_root =
        match verify_block_ad_proofs_with_lookups(prev_hdr, curr_hdr, &ad_bytes, &lookups, &spent, &created) {
            Ok(r) => r,
            Err(e) => return set_err(e.to_string()),
        };

    let leaf_data = match hex32(&fix.merkle_tx_proof.leaf_data) {
        Ok(v) => v,
        Err(e) => return set_err(e),
    };
    let mut levels = Vec::with_capacity(fix.merkle_tx_proof.levels.len());
    for (h, side) in &fix.merkle_tx_proof.levels {
        match hex32(h) {
            Ok(v) => levels.push((v, *side)),
            Err(e) => return set_err(e),
        }
    }
    let tx_proof = ErgoTxMerkleProof { leaf_data, levels };
    if let Err(e) = verify_tx_inclusion(curr_hdr, &tx_proof) {
        return set_err(e.to_string());
    }

    let out = WasmLiveStateOutput {
        live_height: fix.height,
        tip_height: next.tip_height,
        prev_state_root: hex::encode(prev_hdr.state_root),
        next_state_root: hex::encode(new_root),
        ad_bytes: ad_bytes.len(),
        lookup_count: lookups.len(),
        spent_count: spent.len(),
        created_count: created.len(),
        tx_merkle_verified: true,
        verified_tx_id: hex::encode(leaf_data),
    };
    match serde_json::to_vec(&out) {
        Ok(v) => {
            set_output(v);
            0
        }
        Err(e) => set_err(e.to_string()),
    }
}

/// Verify a block `H <= checkpoint.tip_height` directly against a verified `V2Production128`
/// `LightCheckpoint` inside WASM, enforcing:
/// - descending raw header chain `[tip_height, ..., H, H - 1]` authenticated by `BLAKE2b-256`,
/// - `confirmations >= min_confirmations` (defaults to `k_0 = 64` unless explicitly overridden),
/// - `ADProofs` AVL+ state transition (`toLookup ++ toRemove ++ toAppend`, requiring `Some(_)` on lookups),
/// - strict `expected_tx_id == leafData` binding when `expected_tx_id` is supplied.
#[no_mangle]
pub unsafe extern "C" fn wasm_verify_checkpoint_block_state(
    ckpt_ptr: *const u8,
    ckpt_len: usize,
    chain_ptr: *const u8,
    chain_len: usize,
    block_json_ptr: *const u8,
    block_json_len: usize,
) -> i32 {
    let ckpt_bytes = match slice_from_raw_bounded(ckpt_ptr, ckpt_len, MAX_JSON_INPUT_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let chain_bytes = match slice_from_raw_bounded(chain_ptr, chain_len, MAX_EXTENSION_RAW_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };
    let block_bytes = match slice_from_raw_bounded(block_json_ptr, block_json_len, MAX_JSON_INPUT_BYTES) {
        Ok(b) => b,
        Err(e) => return set_err(e),
    };

    let ckpt: LightCheckpoint = match serde_json::from_slice(ckpt_bytes) {
        Ok(c) => c,
        Err(e) => return set_err(format!("checkpoint json: {e}")),
    };
    let inp: WasmCheckpointBlockInput = match serde_json::from_slice(block_bytes) {
        Ok(v) => v,
        Err(e) => return set_err(format!("block proof json: {e}")),
    };
    let ad_bytes = match hex::decode(&inp.ad_proofs_hex) {
        Ok(b) => b,
        Err(e) => return set_err(format!("ad_proofs_hex: {e}")),
    };
    let mut lookups = Vec::with_capacity(inp.lookup_box_ids.len());
    for s in &inp.lookup_box_ids {
        match hex32(s) {
            Ok(id) => lookups.push(id),
            Err(e) => return set_err(e),
        }
    }
    let mut spent = Vec::with_capacity(inp.spent_box_ids.len());
    for s in &inp.spent_box_ids {
        match hex32(s) {
            Ok(id) => spent.push(id),
            Err(e) => return set_err(e),
        }
    }
    let mut created = Vec::with_capacity(inp.created_boxes.len());
    for b in &inp.created_boxes {
        let id = match hex32(&b.box_id) {
            Ok(v) => v,
            Err(e) => return set_err(e),
        };
        let raw = match hex::decode(&b.raw_bytes_hex) {
            Ok(v) => v,
            Err(e) => return set_err(e.to_string()),
        };
        created.push((id, raw));
    }
    let tx_proof = match inp.merkle_tx_proof {
        Some(mp) => {
            let leaf_data = match hex32(&mp.leaf_data) {
                Ok(v) => v,
                Err(e) => return set_err(e),
            };
            let mut levels = Vec::with_capacity(mp.levels.len());
            for (h, side) in &mp.levels {
                match hex32(h) {
                    Ok(v) => levels.push((v, *side)),
                    Err(e) => return set_err(e),
                }
            }
            Some(ErgoTxMerkleProof { leaf_data, levels })
        }
        None => None,
    };
    let expected_tx_id = match inp.expected_tx_id {
        Some(ref s) if !s.is_empty() => match hex32(s) {
            Ok(id) => Some(id),
            Err(e) => return set_err(format!("expected_tx_id: {e}")),
        },
        _ => None,
    };
    let min_confirmations = inp.min_confirmations.unwrap_or(PROD128_MIN_CONFIRMATIONS);

    let res = match verify_checkpoint_block_state(
        &ckpt,
        chain_bytes,
        &ad_bytes,
        &lookups,
        &spent,
        &created,
        tx_proof.as_ref(),
        expected_tx_id,
        min_confirmations,
    ) {
        Ok(v) => v,
        Err(e) => return set_err(e.to_string()),
    };

    let out = WasmCheckpointBlockOutput {
        height: res.height,
        block_id: hex::encode(res.block_id),
        tip_height: ckpt.tip_height,
        confirmations: res.confirmations,
        confirmed_k0: res.confirmed_k0,
        header_chain_len: res.header_chain_len,
        prev_state_root: hex::encode(res.prev_state_root),
        next_state_root: hex::encode(res.next_state_root),
        ad_bytes: res.ad_bytes,
        lookup_count: res.lookup_count,
        spent_count: res.spent_count,
        created_count: res.created_count,
        tx_merkle_verified: res.tx_merkle_verified,
        verified_tx_id: res.verified_tx_id.map(hex::encode),
    };
    match serde_json::to_vec(&out) {
        Ok(v) => {
            set_output(v);
            0
        }
        Err(e) => set_err(e.to_string()),
    }
}
