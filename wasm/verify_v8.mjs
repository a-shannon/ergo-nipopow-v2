#!/usr/bin/env node
// ==============================================================================
// Ergo NiPoPoW V2 — Real V8 WebAssembly Execution Benchmark & Verification
// ==============================================================================
// Zero npm dependencies. Instantiates the compiled `ergo_nipopow_v2_light.wasm`
// module directly inside V8 and verifies:
//   1. Cold V2Production128 verification (.gz ZisK STIR + .gz exact tail)
//   2. Returning-user `extend-tail` (+136 live mainnet headers crossing EIP-37 retarget)
//   3. Live post-STARK block 1,827,976 AVL+ ADProofs & Scorex Tx Merkle proof
//   4. Isolated 1-bit PoW tamper rejection inside WebAssembly (fail-closed)
//   5. `wasm_verify_checkpoint_block_state` (expected_tx_id binding, k_0=64 conf guard,
//      downgraded LightCheckpoint rejection in `wasm_extend_tail`)
//
// Usage:
//   node wasm/verify_v8.mjs <wasm-file> <cert-gz> <tail-gz> <ext-u32le> <live-fixture-json> [vk-csv]
// ==============================================================================

import fs from "node:fs";
import zlib from "node:zlib";
import { performance } from "node:perf_hooks";

const [wasmPath, certPath, tailPath, extPath, fixPath, vkCsv] = process.argv.slice(2);
if (!wasmPath || !certPath || !tailPath || !extPath || !fixPath) {
  console.error(
    "Usage: node wasm/verify_v8.mjs <wasm-file> <cert-bin-or-gz> <tail-u32le-or-gz> <ext-u32le> <live-fixture-json> [vk-csv]"
  );
  process.exit(2);
}

const wasmBytes = fs.readFileSync(wasmPath);
const wasmGzBytes = zlib.gzipSync(wasmBytes, { level: 9 });
console.log(
  `WASM_BINARY_SIZE: raw=${wasmBytes.length} B (${(wasmBytes.length / 1024).toFixed(1)} KiB) gzip9=${wasmGzBytes.length} B (${(wasmGzBytes.length / 1024).toFixed(1)} KiB)`
);

const tInst0 = performance.now();
const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const instMs = performance.now() - tInst0;
const exp = instance.exports;
const dec = new TextDecoder("utf-8");

function allocAndCopy(bytes) {
  const ptr = exp.wasm_alloc(bytes.length) >>> 0;
  if (bytes.length > 0 && ptr === 0) throw new Error(`wasm_alloc failed for ${bytes.length} B`);
  if (bytes.length > 0) new Uint8Array(exp.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function freeBuf(buf) {
  if (buf && buf.ptr !== 0) exp.wasm_dealloc(buf.ptr, buf.len);
}

function readOutput() {
  const ptr = exp.wasm_last_output_ptr() >>> 0;
  const len = exp.wasm_last_output_len() >>> 0;
  return dec.decode(new Uint8Array(exp.memory.buffer, ptr, len));
}

let vkBytes = new Uint8Array(0);
if (vkCsv) {
  const parts = vkCsv.replace(/^\[|\]$/g, "").split(",").map((s) => BigInt(s.trim()));
  if (parts.length !== 4) throw new Error("vk-csv must have 4 u64 limbs");
  vkBytes = new Uint8Array(32);
  const dv = new DataView(vkBytes.buffer);
  for (let i = 0; i < 4; i++) dv.setBigUint64(i * 8, parts[i], true);
}

const certBytes = fs.readFileSync(certPath);
const tailBytes = fs.readFileSync(tailPath);
const extBytes = fs.readFileSync(extPath);
const fixBytes = fs.readFileSync(fixPath);

// [1] Cold 128-bit certificate verification inside V8 WASM
const bCert = allocAndCopy(certBytes);
const bTail = allocAndCopy(tailBytes);
const bVk = allocAndCopy(vkBytes);
const tCold0 = performance.now();
const rcCold = exp.wasm_verify_light_cert(bCert.ptr, bCert.len, bTail.ptr, bTail.len, 1823986, bVk.ptr, bVk.len);
const coldMs = performance.now() - tCold0;
const coldOut = readOutput();
freeBuf(bCert);
freeBuf(bTail);
freeBuf(bVk);
if (rcCold !== 0) {
  console.error("WASM_COLD_VERIFY_FAILED:", coldOut);
  process.exit(1);
}
const coldJson = JSON.parse(coldOut);
if (coldJson.profile !== "V2Production128" || coldJson.openvm_half_verified !== false) {
  throw new Error("Unexpected coldJson metadata: " + coldOut);
}
console.log(
  `WASM_V8_COLD_VERIFY_PASS: inst=${instMs.toFixed(1)}ms cold=${(coldMs / 1000).toFixed(3)}s profile=${coldJson.profile} backend=${coldJson.backend} verified_proof="${coldJson.verified_proof}" h=${coldJson.query_height} tip=${coldJson.tip_height} draws=${coldJson.audit_draws}`
);

// [2] Returning-user extend-tail (+136 live mainnet headers, zero STARK, crosses EIP-37 retarget)
const ckptBytes = Buffer.from(coldJson.checkpoint_json, "utf-8");
const bCkpt = allocAndCopy(ckptBytes);
const bExt = allocAndCopy(extBytes);
const tExt0 = performance.now();
const rcExt = exp.wasm_extend_tail(bCkpt.ptr, bCkpt.len, bExt.ptr, bExt.len);
const extMs = performance.now() - tExt0;
const extOut = readOutput();
if (rcExt !== 0) {
  console.error("WASM_EXTEND_TAIL_FAILED:", extOut);
  process.exit(1);
}
const extJson = JSON.parse(extOut);
console.log(
  `WASM_V8_EXTEND_TAIL_PASS: ${extJson.prev_tip_height} -> ${extJson.tip_height} (+${extJson.headers_verified} headers, zero STARK) elapsed=${extMs.toFixed(1)}ms tip_state_root=${extJson.tip_state_root}`
);

// [3] Live post-STARK block 1,827,976 AVL+ ADProofs & Tx Merkle proof inside V8 WASM
const bFix = allocAndCopy(fixBytes);
const tLive0 = performance.now();
const rcLive = exp.wasm_verify_live_state_proof(bCkpt.ptr, bCkpt.len, bExt.ptr, bExt.len, bFix.ptr, bFix.len);
const liveMs = performance.now() - tLive0;
const liveOut = readOutput();
freeBuf(bFix);
if (rcLive !== 0) {
  console.error("WASM_LIVE_STATE_PROOF_FAILED:", liveOut);
  process.exit(1);
}
const liveJson = JSON.parse(liveOut);
console.log(
  `WASM_V8_LIVE_1827976_STATE_PROOF_PASS: h=${liveJson.live_height} ad_bytes=${liveJson.ad_bytes} spent=${liveJson.spent_count} created=${liveJson.created_count} avl=${liveJson.prev_state_root.slice(0, 12)}..->${liveJson.next_state_root.slice(0, 12)}.. verified_tx=${liveJson.verified_tx_id.slice(0, 12)}.. merkle=${liveJson.tx_merkle_verified} total=${liveMs.toFixed(1)}ms`
);

// [4] Fail-closed 1-bit tamper check inside V8 WASM (flip last PoW nonce bit of block 1,827,976)
const badExt = Buffer.from(extBytes);
badExt[badExt.length - 1] ^= 0x01;
const bBadExt = allocAndCopy(badExt);
const rcBad = exp.wasm_extend_tail(bCkpt.ptr, bCkpt.len, bBadExt.ptr, bBadExt.len);
const badOut = readOutput();
freeBuf(bBadExt);
if (rcBad === 0) {
  console.error("ERROR: tampered extension unexpectedly accepted inside WASM!");
  process.exit(1);
}
console.log(`WASM_V8_TAMPER_REJECTED_OK: ${badOut}`);

// [5] Negative checks: downgraded checkpoint rejected in wasm_extend_tail + txId binding & k_0=64 guard in wasm_verify_checkpoint_block_state
// Replace profile token directly on raw JSON string so u128 integers (total_work) stay exact.
const downgradedStr = coldJson.checkpoint_json.replace('"V2Production128"', '"V2Production"');
if (downgradedStr === coldJson.checkpoint_json) {
  throw new Error("failed to construct downgraded checkpoint string");
}
const bDowngraded = allocAndCopy(Buffer.from(downgradedStr, "utf-8"));
const rcDown = exp.wasm_extend_tail(bDowngraded.ptr, bDowngraded.len, bExt.ptr, bExt.len);
const downOut = readOutput();
freeBuf(bDowngraded);
if (rcDown === 0 || !downOut.includes("unsupported profile V2Production")) {
  console.error("ERROR: expected UnsupportedProfile(V2Production), got rc=" + rcDown + " out=" + downOut);
  process.exit(1);
}
console.log(`WASM_V8_DOWNGRADED_CKPT_REJECTED_OK: ${downOut}`);

// Build descending 2-header chain [1827976, 1827975] from extBytes
const rawHdrs = [];
let pos = 0;
const extDv = new DataView(extBytes.buffer, extBytes.byteOffset, extBytes.byteLength);
while (pos < extBytes.byteLength) {
  const len = extDv.getUint32(pos, true);
  rawHdrs.push(extBytes.subarray(pos + 4, pos + 4 + len));
  pos += 4 + len;
}
const h1 = rawHdrs[rawHdrs.length - 1];
const h0 = rawHdrs[rawHdrs.length - 2];
const chainDesc = Buffer.alloc(4 + h1.length + 4 + h0.length);
chainDesc.writeUInt32LE(h1.length, 0);
Buffer.from(h1).copy(chainDesc, 4);
chainDesc.writeUInt32LE(h0.length, 4 + h1.length);
Buffer.from(h0).copy(chainDesc, 8 + h1.length);

const fixObj = JSON.parse(fixBytes.toString("utf-8"));
const bCkpt1827976 = allocAndCopy(Buffer.from(extJson.checkpoint_json, "utf-8"));
const bChain = allocAndCopy(chainDesc);

// 5a. Default k_0=64 must reject 0-confirmation tip
const bBlockDefault = allocAndCopy(Buffer.from(JSON.stringify({
  ad_proofs_hex: fixObj.ad_proofs_hex,
  spent_box_ids: fixObj.spent_box_ids,
  created_boxes: fixObj.created_boxes,
  merkle_tx_proof: fixObj.merkle_tx_proof,
  expected_tx_id: fixObj.merkle_tx_proof.leafData,
}), "utf-8"));
const rcConf = exp.wasm_verify_checkpoint_block_state(bCkpt1827976.ptr, bCkpt1827976.len, bChain.ptr, bChain.len, bBlockDefault.ptr, bBlockDefault.len);
freeBuf(bBlockDefault);
if (rcConf === 0) throw new Error("0-conf tip passed default k_0=64 check!");

// 5b. Wrong expected_tx_id must reject fail-closed even with min_confirmations=0
const badTx = (fixObj.merkle_tx_proof.leafData[0] === "0" ? "1" : "0") + fixObj.merkle_tx_proof.leafData.slice(1);
const bBlockWrongTx = allocAndCopy(Buffer.from(JSON.stringify({
  ad_proofs_hex: fixObj.ad_proofs_hex,
  spent_box_ids: fixObj.spent_box_ids,
  created_boxes: fixObj.created_boxes,
  merkle_tx_proof: fixObj.merkle_tx_proof,
  expected_tx_id: badTx,
  min_confirmations: 0,
}), "utf-8"));
const rcWrongTx = exp.wasm_verify_checkpoint_block_state(bCkpt1827976.ptr, bCkpt1827976.len, bChain.ptr, bChain.len, bBlockWrongTx.ptr, bBlockWrongTx.len);
freeBuf(bBlockWrongTx);
if (rcWrongTx === 0) throw new Error("mismatched expected_tx_id was accepted!");

// 5c. Matching expected_tx_id with explicit min_confirmations=0 must pass
const bBlockOk = allocAndCopy(Buffer.from(JSON.stringify({
  ad_proofs_hex: fixObj.ad_proofs_hex,
  spent_box_ids: fixObj.spent_box_ids,
  created_boxes: fixObj.created_boxes,
  merkle_tx_proof: fixObj.merkle_tx_proof,
  expected_tx_id: fixObj.merkle_tx_proof.leafData,
  min_confirmations: 0,
}), "utf-8"));
const rcBlockOk = exp.wasm_verify_checkpoint_block_state(bCkpt1827976.ptr, bCkpt1827976.len, bChain.ptr, bChain.len, bBlockOk.ptr, bBlockOk.len);
const blockOkOut = readOutput();
freeBuf(bBlockOk);
freeBuf(bChain);
freeBuf(bCkpt1827976);
freeBuf(bCkpt);
freeBuf(bExt);
if (rcBlockOk !== 0) {
  console.error("WASM_CHECKPOINT_BLOCK_STATE_FAILED:", blockOkOut);
  process.exit(1);
}
const blockOkJson = JSON.parse(blockOkOut);
if (blockOkJson.verified_tx_id !== fixObj.merkle_tx_proof.leafData || blockOkJson.confirmed_k0 !== false) {
  throw new Error("Unexpected blockOkJson: " + blockOkOut);
}
console.log(`WASM_V8_CHECKPOINT_BLOCK_STATE_GUARD_PASS: h=${blockOkJson.height} conf=${blockOkJson.confirmations} confirmed_k0=${blockOkJson.confirmed_k0} verified_tx=${blockOkJson.verified_tx_id.slice(0, 12)}..`);
console.log("=== WASM_V8_ALL_5_CHECKS_PASSED ===");
