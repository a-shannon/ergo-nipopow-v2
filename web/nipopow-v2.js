// ==============================================================================
// Ergo NiPoPoW V2 — Zero-Dependency Browser & Node.js ES Module for V8 WASM
// ==============================================================================
// Wraps `ergo_nipopow_v2_light.wasm` (zero JS imports, zero prover SDK, zero npm)
// with bounded streaming fetches, lossless 64-bit Ergo Long JSON parsing,
// canonical Scorex header & box encoders, and strict fail-closed verification.

const textDec = new TextDecoder("utf-8");
const textEnc = new TextEncoder();

export const MAX_CERT_COMPRESSED_BYTES = 12 * 1024 * 1024;
export const MAX_TAIL_COMPRESSED_BYTES = 8 * 1024 * 1024;
export const MAX_WASM_BYTES = 16 * 1024 * 1024;
export const MAX_NODE_JSON_BYTES = 16 * 1024 * 1024;
export const PROD128_MIN_CONFIRMATIONS = 64;

export function hexToBytes(hex) {
  if (typeof hex !== "string") {
    throw new Error("Expected hex string");
  }
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`Invalid hex string (len=${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function concatBytes(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Losslessly parse JSON while preserving >= 16-digit bare integer tokens (such as
 * Ergo 64-bit `Long` box values and token amounts > 2^53 - 1) as exact decimal strings
 * so JS IEEE-754 `Number` never rounds them before `BigInt` conversion.
 */
export function parseJsonLosslessInts(text) {
  if (typeof text !== "string") throw new Error("Expected JSON string");
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"') {
      const start = i++;
      while (i < n) {
        const c = text[i++];
        if (c === "\\") {
          i++;
        } else if (c === '"') {
          break;
        }
      }
      out += text.slice(start, i);
      continue;
    }
    if ((ch >= "0" && ch <= "9") || (ch === "-" && i + 1 < n && text[i + 1] >= "0" && text[i + 1] <= "9")) {
      const start = i;
      if (text[i] === "-") i++;
      const digitsStart = i;
      while (i < n && text[i] >= "0" && text[i] <= "9") i++;
      const isFloat = i < n && (text[i] === "." || text[i] === "e" || text[i] === "E");
      if (isFloat) {
        while (i < n && /[0-9eE.+\-]/.test(text[i])) i++;
        out += text.slice(start, i);
      } else {
        const digitsLen = i - digitsStart;
        const tok = text.slice(start, i);
        if (digitsLen >= 16) {
          out += `"${tok}"`;
        } else {
          out += tok;
        }
      }
      continue;
    }
    out += ch;
    i++;
  }
  return JSON.parse(out);
}

/**
 * Fetch an HTTP resource with an explicit byte cap (enforced while streaming) and timeout.
 */
export async function fetchBoundedBytes(url, maxBytes, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { signal: ctrl.signal });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} fetching ${url}`);
    }
    const cl = resp.headers?.get?.("content-length");
    if (cl && /^\d+$/.test(cl) && Number(cl) > maxBytes) {
      throw new Error(`Response ${cl} B exceeds cap ${maxBytes} B for ${url}`);
    }
    if (!resp.body || typeof resp.body.getReader !== "function") {
      const buf = new Uint8Array(await resp.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new Error(`Response ${buf.byteLength} B exceeds cap ${maxBytes} B for ${url}`);
      }
      return buf;
    }
    const reader = resp.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {}
        throw new Error(`Streamed response exceeded cap ${maxBytes} B for ${url}`);
      }
      chunks.push(value);
    }
    return concatBytes(chunks);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBoundedJsonLossless(url, maxBytes = MAX_NODE_JSON_BYTES, timeoutMs = 30000) {
  const bytes = await fetchBoundedBytes(url, maxBytes, timeoutMs);
  return parseJsonLosslessInts(textDec.decode(bytes));
}

function toExactNonNegBigInt(value, label = "value") {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error(`Negative ${label}: ${value}`);
    return value;
  }
  if (typeof value === "string") {
    const t = value.trim();
    if (!/^\d+$/.test(t)) throw new Error(`Invalid unsigned integer string for ${label}: ${value}`);
    return BigInt(t);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(
        `Unsafe or negative number for ${label}: ${value} (pass bigint or decimal string for values > 2^53 - 1)`
      );
    }
    return BigInt(value);
  }
  throw new Error(`Unsupported integer type for ${label}: ${typeof value}`);
}

export function encodeVlqUint(value) {
  let v = toExactNonNegBigInt(value, "VLQ");
  const bytes = [];
  while (true) {
    const b = Number(v & 0x7fn);
    v >>= 7n;
    if (v === 0n) {
      bytes.push(b);
      break;
    }
    bytes.push(b | 0x80);
  }
  return new Uint8Array(bytes);
}

/**
 * Canonically serialize an Ergo node output JSON object into exact Scorex
 * `ErgoBoxSerializer` wire bytes (`BLAKE2b-256(bytes) === output.boxId`).
 */
export function encodeErgoBoxJson(o) {
  if (!o || typeof o !== "object") throw new Error("Missing ErgoBox object");
  const assets = o.assets || [];
  if (!Array.isArray(assets) || assets.length > 255) {
    throw new Error(`Invalid ErgoBox asset count: ${assets?.length} (expected 0..=255 UByte)`);
  }
  const indexBig = toExactNonNegBigInt(o.index, "box.index");
  if (indexBig > 65535n) throw new Error(`ErgoBox index out of u16 range: ${indexBig}`);

  const parts = [
    encodeVlqUint(toExactNonNegBigInt(o.value, "box.value")),
    hexToBytes(o.ergoTree),
    encodeVlqUint(toExactNonNegBigInt(o.creationHeight, "box.creationHeight")),
    new Uint8Array([assets.length]),
  ];
  for (const a of assets) {
    const tid = hexToBytes(a.tokenId);
    if (tid.length !== 32) throw new Error(`Invalid tokenId length: ${tid.length}`);
    parts.push(tid, encodeVlqUint(toExactNonNegBigInt(a.amount, "asset.amount")));
  }
  const regs = o.additionalRegisters || {};
  const regKeys = Object.keys(regs).sort();
  if (regKeys.length > 6) throw new Error(`Too many additional registers: ${regKeys.length}`);
  // Scorex ErgoBox requires dense ascending registers R4..R{3 + k}
  for (let i = 0; i < regKeys.length; i++) {
    const expectedKey = `R${4 + i}`;
    if (regKeys[i] !== expectedKey) {
      throw new Error(`Non-canonical register key ${regKeys[i]} (expected dense ${expectedKey})`);
    }
  }
  parts.push(new Uint8Array([regKeys.length]));
  for (const k of regKeys) {
    parts.push(hexToBytes(regs[k]));
  }
  const txId = hexToBytes(o.transactionId);
  if (txId.length !== 32) throw new Error(`Invalid box.transactionId length: ${txId.length}`);
  parts.push(txId, encodeVlqUint(indexBig));
  return concatBytes(parts);
}

/**
 * Extract consensus-exact Ergo `StateChanges` (`toLookup ++ toRemove ++ toAppend`)
 * matching `org.ergoplatform.nodeView.state.ErgoState.stateChanges` / `boxChanges`
 * (intra-block spend cancellation, duplicate external spend rejection, and
 * lexicographical lowercase hex `boxId` sorting).
 */
export function extractBlockStateChanges(blockJson) {
  const txs = blockJson?.blockTransactions?.transactions;
  if (!Array.isArray(txs)) {
    throw new Error("Malformed block JSON: missing blockTransactions.transactions");
  }
  const toRemove = new Map();
  const toInsert = new Map();
  const lookupBoxIds = [];
  for (const tx of txs) {
    for (const di of tx.dataInputs || []) {
      const id = String(di.boxId || "").toLowerCase();
      if (id.length !== 64 || !/^[0-9a-f]{64}$/.test(id)) {
        throw new Error(`Invalid dataInput boxId: ${di.boxId}`);
      }
      lookupBoxIds.push(id);
    }
    for (const inp of tx.inputs || []) {
      const id = String(inp.boxId || "").toLowerCase();
      if (id.length !== 64 || !/^[0-9a-f]{64}$/.test(id)) {
        throw new Error(`Invalid input boxId: ${inp.boxId}`);
      }
      if (toInsert.has(id)) {
        toInsert.delete(id);
      } else {
        if (toRemove.has(id)) {
          throw new Error(`Duplicate external spend of input boxId ${id} in block`);
        }
        toRemove.set(id, true);
      }
    }
    for (const out of tx.outputs || []) {
      const id = String(out.boxId || "").toLowerCase();
      if (id.length !== 64 || !/^[0-9a-f]{64}$/.test(id)) {
        throw new Error(`Invalid output boxId: ${out.boxId}`);
      }
      toInsert.set(id, { box_id: id, raw_bytes_hex: bytesToHex(encodeErgoBoxJson(out)) });
    }
  }
  const spentBoxIds = Array.from(toRemove.keys()).sort();
  const createdBoxes = Array.from(toInsert.keys())
    .sort()
    .map((id) => toInsert.get(id));
  return {
    ad_proofs_hex: blockJson?.adProofs?.proofBytes || "",
    lookup_box_ids: lookupBoxIds,
    spent_box_ids: spentBoxIds,
    created_boxes: createdBoxes,
    node_reported_tx_count: txs.length,
    tx_ids: txs.map((t) => String(t.id || "").toLowerCase()),
  };
}

/**
 * Canonically encode a modern Ergo header JSON object (version >= 2) into Scorex binary
 * wire bytes matching `ergo-nipopow-v2-core::header::Header`.
 */
export function encodeErgoHeaderJson(h) {
  if (!h || typeof h !== "object") throw new Error("Missing header object");
  const version = Number(h.version);
  if (!Number.isInteger(version) || version < 2 || version > 127) {
    throw new Error(`Expected modern Ergo header version 2..=127, got ${h.version}`);
  }
  const parentId = hexToBytes(h.parentId);
  const adProofsRoot = hexToBytes(h.adProofsRoot);
  const transactionsRoot = hexToBytes(h.transactionsRoot);
  const stateRoot = hexToBytes(h.stateRoot);
  const tsVlq = encodeVlqUint(toExactNonNegBigInt(h.timestamp, "header.timestamp"));
  const extensionHash = hexToBytes(h.extensionHash);
  const nBitsNum = Number(h.nBits);
  if (!Number.isInteger(nBitsNum) || nBitsNum < -2147483648 || nBitsNum > 4294967295) {
    throw new Error(`Invalid header.nBits: ${h.nBits}`);
  }
  const nBitsBuf = new Uint8Array(4);
  new DataView(nBitsBuf.buffer).setUint32(0, nBitsNum >>> 0, false);
  const heightVlq = encodeVlqUint(toExactNonNegBigInt(h.height, "header.height"));
  const votes = hexToBytes(h.votes);
  const unparsed = h.unparsedBytes ? hexToBytes(h.unparsedBytes) : new Uint8Array(0);
  if (unparsed.length > 255) {
    throw new Error(`Header unparsedBytes length ${unparsed.length} exceeds 255`);
  }
  if (version <= 4 && unparsed.length > 0) {
    throw new Error(`Non-empty unparsedBytes forbidden for header version ${version}`);
  }
  if (!h.powSolutions || typeof h.powSolutions !== "object") {
    throw new Error(`Missing powSolutions at height ${h.height}`);
  }
  const pk = hexToBytes(h.powSolutions.pk);
  const nonce = hexToBytes(h.powSolutions.n);

  if (
    parentId.length !== 32 ||
    adProofsRoot.length !== 32 ||
    transactionsRoot.length !== 32 ||
    stateRoot.length !== 33 ||
    extensionHash.length !== 32 ||
    votes.length !== 3 ||
    pk.length !== 33 ||
    nonce.length !== 8
  ) {
    throw new Error(`Malformed header field lengths at height ${h.height}`);
  }

  const total =
    1 + 32 + 32 + 32 + 33 + tsVlq.length + 32 + 4 + heightVlq.length + 3 + 1 + unparsed.length + 33 + 8;
  if (total > 514) {
    throw new Error(`Encoded header length ${total} exceeds Ergo 514-byte maximum`);
  }
  const out = new Uint8Array(total);
  let p = 0;
  out[p++] = version & 0xff;
  out.set(parentId, p);
  p += 32;
  out.set(adProofsRoot, p);
  p += 32;
  out.set(transactionsRoot, p);
  p += 32;
  out.set(stateRoot, p);
  p += 33;
  out.set(tsVlq, p);
  p += tsVlq.length;
  out.set(extensionHash, p);
  p += 32;
  out.set(nBitsBuf, p);
  p += 4;
  out.set(heightVlq, p);
  p += heightVlq.length;
  out.set(votes, p);
  p += 3;
  out[p++] = unparsed.length & 0xff;
  if (unparsed.length > 0) {
    out.set(unparsed, p);
    p += unparsed.length;
  }
  out.set(pk, p);
  p += 33;
  out.set(nonce, p);
  p += 8;
  return out;
}

/**
 * Pack an ordered array of Ergo header JSON objects into a length-prefixed `.u32le` stream.
 */
export function encodeU32leStream(headersJson) {
  const encoded = headersJson.map(encodeErgoHeaderJson);
  const totalBytes = encoded.reduce((acc, b) => acc + 4 + b.length, 0);
  const out = new Uint8Array(totalBytes);
  const dv = new DataView(out.buffer);
  let pos = 0;
  for (const raw of encoded) {
    dv.setUint32(pos, raw.length, true);
    pos += 4;
    out.set(raw, pos);
    pos += raw.length;
  }
  return out;
}

/**
 * Fetch strictly contiguous live Ergo headers in `(fromHeightExclusive, toHeightInclusive]`
 * from any untrusted Ergo node REST API (`/blocks/chainSlice`), rejecting gaps, duplicates,
 * stalled cursors, or oversized payloads.
 */
export async function fetchLiveHeadersU32le(
  nodeUrl,
  fromHeightExclusive,
  toHeightInclusive,
  onProgress = null
) {
  if (!Number.isInteger(fromHeightExclusive) || !Number.isInteger(toHeightInclusive)) {
    throw new Error("fromHeightExclusive and toHeightInclusive must be integers");
  }
  if (toHeightInclusive <= fromHeightExclusive) {
    throw new Error(`Invalid height range (${fromHeightExclusive}, ${toHeightInclusive}]`);
  }
  const base = nodeUrl.replace(/\/+$/, "");
  const allHeaders = [];
  const batchSize = 256;
  let cursor = fromHeightExclusive;
  while (cursor < toHeightInclusive) {
    const nextTo = Math.min(cursor + batchSize, toHeightInclusive);
    const url = `${base}/blocks/chainSlice?fromHeight=${cursor}&toHeight=${nextTo}`;
    const batch = await fetchBoundedJsonLossless(url, MAX_NODE_JSON_BYTES);
    if (!Array.isArray(batch) || batch.length === 0) {
      throw new Error(`Empty chainSlice returned for (${cursor}, ${nextTo}]`);
    }
    const byHeight = new Map();
    for (const h of batch) {
      const hh = Number(h?.height);
      if (Number.isInteger(hh) && hh > cursor && hh <= nextTo) {
        if (byHeight.has(hh)) {
          throw new Error(`Duplicate header returned at height ${hh}`);
        }
        byHeight.set(hh, h);
      }
    }
    const expectedCount = nextTo - cursor;
    for (let h = cursor + 1; h <= nextTo; h++) {
      const hdr = byHeight.get(h);
      if (!hdr) {
        throw new Error(
          `Incomplete chainSlice: missing height ${h} in requested (${cursor}, ${nextTo}] (got ${byHeight.size}/${expectedCount})`
        );
      }
      allHeaders.push(hdr);
    }
    cursor = nextTo;
    if (onProgress) {
      onProgress({ fetched: allHeaders.length, tipHeight: cursor, targetHeight: toHeightInclusive });
    }
  }
  return {
    headers: allHeaders,
    u32le: encodeU32leStream(allHeaders),
  };
}

/**
 * Fetch a live block's descending header chain `[tip, ..., target, target - 1]`, real `ADProofs`,
 * full `StateChanges` (including `dataInputs` & intra-block spend cancellation), and Scorex
 * transaction Merkle inclusion proof from an untrusted Ergo node.
 *
 * Fetches `/blocks/${blockId}` using the EXACT `blockId` taken from the descending header chain
 * (never `/blocks/at/{H}`) so a concurrent reorg cannot mix branches, and passes `expected_tx_id`
 * + `min_confirmations` directly into WASM for strict fail-closed binding.
 */
export async function fetchLiveBlockProofBundle(
  nodeUrl,
  checkpointTipHeight,
  targetHeight,
  txSelector = 0,
  minConfirmations = PROD128_MIN_CONFIRMATIONS
) {
  const base = nodeUrl.replace(/\/+$/, "");
  if (!Number.isInteger(targetHeight) || !Number.isInteger(checkpointTipHeight)) {
    throw new Error("targetHeight and checkpointTipHeight must be integers");
  }
  if (targetHeight > checkpointTipHeight) {
    throw new Error(
      `Target height ${targetHeight} is ahead of certified checkpoint tip ${checkpointTipHeight}. Sync headers first.`
    );
  }
  if (targetHeight < 2) {
    throw new Error(`Target height must be >= 2, got ${targetHeight}`);
  }
  if (checkpointTipHeight - targetHeight > 1024) {
    throw new Error(
      `Target height ${targetHeight} is more than 1,024 blocks behind tip ${checkpointTipHeight} (max browser walk: 1,024)`
    );
  }
  const confirmations = checkpointTipHeight - targetHeight;
  if (confirmations < minConfirmations) {
    throw new Error(
      `Block ${targetHeight} has only ${confirmations} confirmations below tip ${checkpointTipHeight} (required >= ${minConfirmations}). Enable unconfirmed inspection explicitly or choose height <= ${checkpointTipHeight - minConfirmations}.`
    );
  }

  const { headers } = await fetchLiveHeadersU32le(nodeUrl, targetHeight - 2, checkpointTipHeight);
  const descHeaders = headers.slice().reverse();
  const targetHeader = descHeaders[descHeaders.length - 2];
  const blockId = String(targetHeader?.id || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(blockId)) {
    throw new Error(`Missing valid header.id at height ${targetHeight} in chainSlice`);
  }
  const headerChainDescU32le = encodeU32leStream(descHeaders);

  const blockJson = await fetchBoundedJsonLossless(`${base}/blocks/${blockId}`, MAX_NODE_JSON_BYTES);
  if (String(blockJson?.header?.id || "").toLowerCase() !== blockId || Number(blockJson?.header?.height) !== targetHeight) {
    throw new Error(`Node returned mismatched block for certified id ${blockId}`);
  }
  const changes = extractBlockStateChanges(blockJson);
  if (!changes.ad_proofs_hex) {
    throw new Error(`Node did not return adProofs.proofBytes for block ${targetHeight}`);
  }

  let requestedTxId = null;
  if (typeof txSelector === "string" && txSelector.trim().length > 0) {
    const clean = txSelector.trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(clean)) {
      requestedTxId = clean;
    } else if (/^\d+$/.test(clean)) {
      const idx = Number(clean);
      if (idx >= changes.tx_ids.length) {
        throw new Error(`Tx index ${idx} out of range (block has ${changes.tx_ids.length} txs)`);
      }
      requestedTxId = changes.tx_ids[idx];
    } else {
      throw new Error(`Invalid txSelector "${txSelector}": expected tx index or 64-hex txId`);
    }
  } else if (typeof txSelector === "number") {
    if (!Number.isInteger(txSelector) || txSelector < 0 || txSelector >= changes.tx_ids.length) {
      throw new Error(`Tx index ${txSelector} out of range (block has ${changes.tx_ids.length} txs)`);
    }
    requestedTxId = changes.tx_ids[txSelector];
  }

  let merkleTxProof = null;
  if (requestedTxId) {
    merkleTxProof = await fetchBoundedJsonLossless(
      `${base}/blocks/${blockId}/proofFor/${requestedTxId}`,
      1024 * 1024
    );
  }

  const blockProofJson = JSON.stringify({
    ad_proofs_hex: changes.ad_proofs_hex,
    lookup_box_ids: changes.lookup_box_ids,
    spent_box_ids: changes.spent_box_ids,
    created_boxes: changes.created_boxes,
    merkle_tx_proof: merkleTxProof,
    expected_tx_id: requestedTxId,
    min_confirmations: minConfirmations,
  });

  return {
    blockId,
    targetHeight,
    requestedTxId,
    nodeReportedTxCount: changes.node_reported_tx_count,
    headerChainDescU32le,
    blockProofJson,
  };
}

export class NiPoPoWV2Wasm {
  constructor(instance, instantiateMs) {
    this.instance = instance;
    this.exp = instance.exports;
    this.instantiateMs = instantiateMs;
    this._poisoned = false;
  }

  static async load(wasmBytes) {
    if (!wasmBytes || wasmBytes.byteLength === 0 || wasmBytes.byteLength > MAX_WASM_BYTES) {
      throw new Error(`Invalid WASM binary size: ${wasmBytes?.byteLength}`);
    }
    const t0 = performance.now();
    const { instance } = await WebAssembly.instantiate(wasmBytes, {});
    return new NiPoPoWV2Wasm(instance, performance.now() - t0);
  }

  _ensureHealthy() {
    if (this._poisoned) {
      throw new Error("WASM instance trapped previously; reload with NiPoPoWV2Wasm.load(...)");
    }
  }

  _allocCopy(bytes, tracked) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const ptr = this.exp.wasm_alloc(u8.length) >>> 0;
    if (u8.length > 0 && ptr === 0) {
      throw new Error(`WASM allocation refused or failed for ${u8.length} bytes (exceeds cap or OOM)`);
    }
    if (u8.length > 0) {
      new Uint8Array(this.exp.memory.buffer, ptr, u8.length).set(u8);
    }
    const buf = { ptr, len: u8.length };
    tracked.push(buf);
    return buf;
  }

  _freeAll(tracked) {
    if (this._poisoned) return;
    for (const buf of tracked) {
      try {
        if (buf.ptr !== 0) {
          this.exp.wasm_dealloc(buf.ptr, buf.len);
        }
      } catch {
        this._poisoned = true;
        break;
      }
    }
  }

  _readOutput() {
    const ptr = this.exp.wasm_last_output_ptr() >>> 0;
    const len = this.exp.wasm_last_output_len() >>> 0;
    return textDec.decode(new Uint8Array(this.exp.memory.buffer, ptr, len));
  }

  verifyCert(certBytes, tailBytes, queryHeight = 1823986, vkCsv = "") {
    this._ensureHealthy();
    let vkBytes = new Uint8Array(0);
    if (vkCsv && vkCsv.trim().length > 0) {
      const parts = vkCsv
        .replace(/^\[|\]$/g, "")
        .split(",")
        .map((s) => BigInt(s.trim()));
      if (parts.length !== 4) throw new Error("vkCsv must contain 4 u64 limbs");
      vkBytes = new Uint8Array(32);
      const dv = new DataView(vkBytes.buffer);
      for (let i = 0; i < 4; i++) dv.setBigUint64(i * 8, parts[i], true);
    }
    const tracked = [];
    try {
      const bCert = this._allocCopy(certBytes, tracked);
      const bTail = this._allocCopy(tailBytes, tracked);
      const bVk = this._allocCopy(vkBytes, tracked);
      const t0 = performance.now();
      const rc = this.exp.wasm_verify_light_cert(
        bCert.ptr,
        bCert.len,
        bTail.ptr,
        bTail.len,
        queryHeight,
        bVk.ptr,
        bVk.len
      );
      const elapsedMs = performance.now() - t0;
      const rawOut = this._readOutput();
      if (rc !== 0) throw new Error(rawOut);
      return { ...JSON.parse(rawOut), elapsedMs };
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError) this._poisoned = true;
      throw e;
    } finally {
      this._freeAll(tracked);
    }
  }

  extendTail(checkpointJson, extU32leBytes, nowMs = 0) {
    this._ensureHealthy();
    const tracked = [];
    try {
      const bCkpt = this._allocCopy(textEnc.encode(checkpointJson), tracked);
      const bExt = this._allocCopy(extU32leBytes, tracked);
      const t0 = performance.now();
      const rc =
        typeof this.exp.wasm_extend_tail_at_time === "function"
          ? this.exp.wasm_extend_tail_at_time(
              bCkpt.ptr,
              bCkpt.len,
              bExt.ptr,
              bExt.len,
              BigInt(Math.max(0, Math.trunc(nowMs || 0)))
            )
          : this.exp.wasm_extend_tail(bCkpt.ptr, bCkpt.len, bExt.ptr, bExt.len);
      const elapsedMs = performance.now() - t0;
      const rawOut = this._readOutput();
      if (rc !== 0) throw new Error(rawOut);
      return { ...JSON.parse(rawOut), elapsedMs };
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError) this._poisoned = true;
      throw e;
    } finally {
      this._freeAll(tracked);
    }
  }

  verifyLiveStateProof(checkpointJson, extU32leBytes, fixtureJsonBytes) {
    this._ensureHealthy();
    const tracked = [];
    try {
      const bCkpt = this._allocCopy(textEnc.encode(checkpointJson), tracked);
      const bExt = this._allocCopy(extU32leBytes, tracked);
      const bFix = this._allocCopy(
        typeof fixtureJsonBytes === "string" ? textEnc.encode(fixtureJsonBytes) : fixtureJsonBytes,
        tracked
      );
      const t0 = performance.now();
      const rc = this.exp.wasm_verify_live_state_proof(
        bCkpt.ptr,
        bCkpt.len,
        bExt.ptr,
        bExt.len,
        bFix.ptr,
        bFix.len
      );
      const elapsedMs = performance.now() - t0;
      const rawOut = this._readOutput();
      if (rc !== 0) throw new Error(rawOut);
      return { ...JSON.parse(rawOut), elapsedMs };
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError) this._poisoned = true;
      throw e;
    } finally {
      this._freeAll(tracked);
    }
  }

  verifyCheckpointBlockState(checkpointJson, headerChainDescU32le, blockProofJson) {
    this._ensureHealthy();
    const tracked = [];
    try {
      const bCkpt = this._allocCopy(textEnc.encode(checkpointJson), tracked);
      const bChain = this._allocCopy(headerChainDescU32le, tracked);
      const bBlock = this._allocCopy(
        typeof blockProofJson === "string" ? textEnc.encode(blockProofJson) : blockProofJson,
        tracked
      );
      const t0 = performance.now();
      const rc = this.exp.wasm_verify_checkpoint_block_state(
        bCkpt.ptr,
        bCkpt.len,
        bChain.ptr,
        bChain.len,
        bBlock.ptr,
        bBlock.len
      );
      const elapsedMs = performance.now() - t0;
      const rawOut = this._readOutput();
      if (rc !== 0) throw new Error(rawOut);
      return { ...JSON.parse(rawOut), elapsedMs };
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError) this._poisoned = true;
      throw e;
    } finally {
      this._freeAll(tracked);
    }
  }
}
