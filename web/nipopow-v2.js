// ==============================================================================
// Ergo NiPoPoW V2 — Zero-Dependency Browser & Node.js ES Module for V8 WASM
// ==============================================================================
// Wraps `ergo_nipopow_v2_light.wasm` (zero JS imports, zero prover SDK, zero npm)
// and provides a canonical Ergo Scorex binary header encoder so clients can sync
// indefinitely from any untrusted Ergo node REST API (`/blocks/chainSlice`).

const textDec = new TextDecoder("utf-8");
const textEnc = new TextEncoder();

export function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex string length: ${clean.length}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function encodeVlqUint(value) {
  let v = typeof value === "bigint" ? value : BigInt(value);
  if (v < 0n) throw new Error(`Negative VLQ value: ${v}`);
  const bytes = [];
  while (true) {
    let b = Number(v & 0x7fn);
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
 * Canonically encode a modern Ergo header JSON object (as returned by Ergo node
 * `/blocks/chainSlice` or `/blocks/{id}/header`, version >= 2) into Scorex binary
 * wire bytes matching `ergo-nipopow-v2-core::header::Header::parse_raw`.
 */
export function encodeErgoHeaderJson(h) {
  const version = Number(h.version);
  if (!Number.isInteger(version) || version < 2 || version > 127) {
    throw new Error(`Expected modern Ergo header version >= 2, got ${h.version}`);
  }
  const parentId = hexToBytes(h.parentId);
  const adProofsRoot = hexToBytes(h.adProofsRoot);
  const transactionsRoot = hexToBytes(h.transactionsRoot);
  const stateRoot = hexToBytes(h.stateRoot);
  const tsVlq = encodeVlqUint(BigInt(h.timestamp));
  const extensionHash = hexToBytes(h.extensionHash);
  const nBitsBuf = new Uint8Array(4);
  new DataView(nBitsBuf.buffer).setUint32(0, Number(h.nBits) >>> 0, false);
  const heightVlq = encodeVlqUint(BigInt(h.height));
  const votes = hexToBytes(h.votes);
  const unparsed = h.unparsedBytes ? hexToBytes(h.unparsedBytes) : new Uint8Array(0);
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
    1 +
    32 +
    32 +
    32 +
    33 +
    tsVlq.length +
    32 +
    4 +
    heightVlq.length +
    3 +
    1 +
    unparsed.length +
    33 +
    8;
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
 * Fetch live Ergo headers in `(fromHeightExclusive, toHeightInclusive]` from any
 * untrusted Ergo node REST API (`/blocks/chainSlice`), returning a canonical `.u32le` stream.
 */
export async function fetchLiveHeadersU32le(
  nodeUrl,
  fromHeightExclusive,
  toHeightInclusive,
  onProgress = null
) {
  const base = nodeUrl.replace(/\/+$/, "");
  const allHeaders = [];
  const batchSize = 256;
  let cursor = fromHeightExclusive;
  while (cursor < toHeightInclusive) {
    const nextTo = Math.min(cursor + batchSize, toHeightInclusive);
    const url = `${base}/blocks/chainSlice?fromHeight=${cursor}&toHeight=${nextTo}`;
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`Node HTTP ${resp.status} fetching ${url}`);
    }
    const batch = await resp.json();
    if (!Array.isArray(batch) || batch.length === 0) {
      throw new Error(`Empty chainSlice returned for (${cursor}, ${nextTo}]`);
    }
    batch.sort((a, b) => a.height - b.height);
    for (const h of batch) {
      if (h.height > cursor && h.height <= nextTo) {
        allHeaders.push(h);
      }
    }
    cursor = allHeaders[allHeaders.length - 1].height;
    if (onProgress) {
      onProgress({ fetched: allHeaders.length, tipHeight: cursor, targetHeight: toHeightInclusive });
    }
  }
  return {
    headers: allHeaders,
    u32le: encodeU32leStream(allHeaders),
  };
}

export class NiPoPoWV2Wasm {
  constructor(instance, instantiateMs) {
    this.instance = instance;
    this.exp = instance.exports;
    this.instantiateMs = instantiateMs;
  }

  static async load(wasmBytes) {
    const t0 = performance.now();
    const { instance } = await WebAssembly.instantiate(wasmBytes, {});
    return new NiPoPoWV2Wasm(instance, performance.now() - t0);
  }

  _allocCopy(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const ptr = this.exp.wasm_alloc(u8.length);
    new Uint8Array(this.exp.memory.buffer, ptr, u8.length).set(u8);
    return { ptr, len: u8.length };
  }

  _free(buf) {
    this.exp.wasm_dealloc(buf.ptr, buf.len);
  }

  _readOutput() {
    const ptr = this.exp.wasm_last_output_ptr();
    const len = this.exp.wasm_last_output_len();
    return textDec.decode(new Uint8Array(this.exp.memory.buffer, ptr, len));
  }

  verifyCert(certBytes, tailBytes, queryHeight = 1823986, vkCsv = "") {
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
    const bCert = this._allocCopy(certBytes);
    const bTail = this._allocCopy(tailBytes);
    const bVk = this._allocCopy(vkBytes);
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
    this._free(bCert);
    this._free(bTail);
    this._free(bVk);
    if (rc !== 0) {
      throw new Error(rawOut);
    }
    return { ...JSON.parse(rawOut), elapsedMs };
  }

  extendTail(checkpointJson, extU32leBytes) {
    const bCkpt = this._allocCopy(textEnc.encode(checkpointJson));
    const bExt = this._allocCopy(extU32leBytes);
    const t0 = performance.now();
    const rc = this.exp.wasm_extend_tail(bCkpt.ptr, bCkpt.len, bExt.ptr, bExt.len);
    const elapsedMs = performance.now() - t0;
    const rawOut = this._readOutput();
    this._free(bCkpt);
    this._free(bExt);
    if (rc !== 0) {
      throw new Error(rawOut);
    }
    return { ...JSON.parse(rawOut), elapsedMs };
  }

  verifyLiveStateProof(checkpointJson, extU32leBytes, fixtureJsonBytes) {
    const bCkpt = this._allocCopy(textEnc.encode(checkpointJson));
    const bExt = this._allocCopy(extU32leBytes);
    const bFix = this._allocCopy(
      typeof fixtureJsonBytes === "string" ? textEnc.encode(fixtureJsonBytes) : fixtureJsonBytes
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
    this._free(bCkpt);
    this._free(bExt);
    this._free(bFix);
    if (rc !== 0) {
      throw new Error(rawOut);
    }
    return { ...JSON.parse(rawOut), elapsedMs };
  }
}
