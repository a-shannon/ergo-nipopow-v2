// Dedicated Web Worker keeping Ergo NiPoPoW V2 WASM verification off the UI thread.
import {
  NiPoPoWV2Wasm,
  PROD128_MIN_CONFIRMATIONS,
  fetchLiveHeadersU32le,
  fetchLiveBlockProofBundle,
  fetchBoundedBytes,
  parseJsonLosslessInts,
} from "./nipopow-v2.js";

let wasmClient = null;
let lastWasmBytes = null;

async function ensureClient() {
  if (!wasmClient) throw new Error("WASM not initialized");
  if (wasmClient._poisoned && lastWasmBytes) {
    wasmClient = await NiPoPoWV2Wasm.load(lastWasmBytes);
  }
  return wasmClient;
}

self.onmessage = async (ev) => {
  const { id, type, payload } = ev.data;
  try {
    if (type === "init") {
      lastWasmBytes = payload.wasmBytes;
      wasmClient = await NiPoPoWV2Wasm.load(payload.wasmBytes);
      self.postMessage({
        id,
        ok: true,
        result: { instantiateMs: wasmClient.instantiateMs, rawBytes: payload.wasmBytes.byteLength },
      });
    } else if (type === "verifyCert") {
      const client = await ensureClient();
      const res = client.verifyCert(
        payload.certBytes,
        payload.tailBytes,
        payload.queryHeight ?? 1823986,
        payload.vkCsv ?? ""
      );
      self.postMessage({ id, ok: true, result: res });
    } else if (type === "extendTail") {
      const client = await ensureClient();
      const res = client.extendTail(payload.checkpointJson, payload.extBytes, payload.nowMs ?? 0);
      self.postMessage({ id, ok: true, result: res });
    } else if (type === "extendLiveFromNode") {
      const client = await ensureClient();
      const { nodeUrl, checkpointJson, count } = payload;
      const ckptObj = JSON.parse(checkpointJson);
      const fromH = ckptObj.tip_height;
      const base = nodeUrl.replace(/\/+$/, "");
      const infoRaw = await fetchBoundedBytes(`${base}/info`, 1024 * 1024);
      const info = parseJsonLosslessInts(new TextDecoder().decode(infoRaw));
      const nodeTip = Number(info.headersHeight ?? info.fullHeight);
      const nodeFullHeight = Number(info.fullHeight ?? nodeTip);
      if (!Number.isInteger(nodeTip) || nodeTip < fromH) {
        throw new Error(`Node tip (${nodeTip}) is behind checkpoint (${fromH})`);
      }
      if (nodeTip === fromH) {
        const atRaw = await fetchBoundedBytes(`${base}/blocks/at/${fromH}`, 64 * 1024);
        const ids = JSON.parse(new TextDecoder().decode(atRaw));
        const nodeId = String(ids?.[0] || "").toLowerCase();
        const ckptId = Array.isArray(ckptObj.tip_id)
          ? ckptObj.tip_id.map((b) => b.toString(16).padStart(2, "0")).join("")
          : String(ckptObj.tip_id || "").toLowerCase();
        if (nodeId && ckptId && nodeId !== ckptId) {
          throw new Error(
            `Same-height fork detected at ${fromH}: node id ${nodeId.slice(0, 12)}.. != checkpoint id ${ckptId.slice(0, 12)}.. (re-run step 1 cold verify to reorg cleanly)`
          );
        }
        throw new Error(`Already synced to node tip height ${fromH}`);
      }
      const targetH = count > 0 ? Math.min(fromH + count, nodeTip) : nodeTip;
      const { u32le } = await fetchLiveHeadersU32le(nodeUrl, fromH, targetH, (prog) => {
        self.postMessage({ id, progress: prog });
      });
      const res = client.extendTail(checkpointJson, u32le, Date.now());
      self.postMessage({
        id,
        ok: true,
        result: {
          ...res,
          nodeTipHeight: nodeTip,
          nodeFullHeight,
          wireBytes: u32le.byteLength,
        },
      });
    } else if (type === "verifyLiveStateProof") {
      const client = await ensureClient();
      const res = client.verifyLiveStateProof(
        payload.checkpointJson,
        payload.extBytes,
        payload.fixtureBytes
      );
      self.postMessage({ id, ok: true, result: res });
    } else if (type === "verifyLiveBlockFromNode") {
      const client = await ensureClient();
      const { nodeUrl, checkpointJson, targetHeight, txSelector, allowUnconfirmed } = payload;
      const ckpt = JSON.parse(checkpointJson);
      const minConf = allowUnconfirmed ? 0 : PROD128_MIN_CONFIRMATIONS;
      const defaultH = allowUnconfirmed
        ? ckpt.tip_height
        : Math.max(2, ckpt.tip_height - PROD128_MIN_CONFIRMATIONS);
      const h = targetHeight > 0 ? targetHeight : defaultH;
      const bundle = await fetchLiveBlockProofBundle(nodeUrl, ckpt.tip_height, h, txSelector, minConf);
      const res = client.verifyCheckpointBlockState(
        checkpointJson,
        bundle.headerChainDescU32le,
        bundle.blockProofJson
      );
      self.postMessage({
        id,
        ok: true,
        result: {
          ...res,
          node_reported_tx_count: bundle.nodeReportedTxCount,
        },
      });
    } else {
      throw new Error(`Unknown worker action: ${type}`);
    }
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message || err) });
  }
};
