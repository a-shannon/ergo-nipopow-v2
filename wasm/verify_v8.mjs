#!/usr/bin/env node
// ==============================================================================
// Ergo NiPoPoW V2 — Real V8 WebAssembly Execution Benchmark & Verification
// ==============================================================================
// Zero npm dependencies. Instantiates the compiled `ergo_nipopow_v2_light.wasm`
// module directly inside V8 (the same engine used by Chromium / Android Chrome)
// and verifies:
//   1. Cold 128-bit certificate verification (.gz ZisK STIR + .gz exact tail)
//   2. Returning-user `extend-tail` (+136 live mainnet headers crossing EIP-37 retarget)
//   3. Live post-STARK block 1,827,976 AVL+ ADProofs & Scorex Tx Merkle proof
//   4. Isolated 1-bit tamper rejection inside WebAssembly (fail-closed)
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
  const ptr = exp.wasm_alloc(bytes.length);
  new Uint8Array(exp.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function freeBuf(buf) {
  exp.wasm_dealloc(buf.ptr, buf.len);
}

function readOutput() {
  const ptr = exp.wasm_last_output_ptr();
  const len = exp.wasm_last_output_len();
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
console.log(
  `WASM_V8_COLD_VERIFY_PASS: inst=${instMs.toFixed(1)}ms cold=${(coldMs / 1000).toFixed(3)}s profile=${coldJson.profile} backend=${coldJson.backend} h=${coldJson.query_height} tip=${coldJson.tip_height} draws=${coldJson.audit_draws}`
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
  `WASM_V8_LIVE_1827976_STATE_PROOF_PASS: h=${liveJson.live_height} ad_bytes=${liveJson.ad_bytes} spent=${liveJson.spent_count} created=${liveJson.created_count} avl=${liveJson.prev_state_root.slice(0, 12)}..->${liveJson.next_state_root.slice(0, 12)}.. tx_merkle=${liveJson.tx_merkle_verified} total=${liveMs.toFixed(1)}ms`
);

// [4] Fail-closed 1-bit tamper check inside V8 WASM (flip last PoW nonce bit of block 1,827,976)
const badExt = Buffer.from(extBytes);
badExt[badExt.length - 1] ^= 0x01;
const bBadExt = allocAndCopy(badExt);
const rcBad = exp.wasm_extend_tail(bCkpt.ptr, bCkpt.len, bBadExt.ptr, bBadExt.len);
const badOut = readOutput();
freeBuf(bBadExt);
freeBuf(bCkpt);
freeBuf(bExt);
if (rcBad === 0) {
  console.error("ERROR: tampered extension unexpectedly accepted inside WASM!");
  process.exit(1);
}
console.log(`WASM_V8_TAMPER_REJECTED_OK: ${badOut}`);
console.log("=== WASM_V8_ALL_4_CHECKS_PASSED ===");
