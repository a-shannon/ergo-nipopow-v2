// Dedicated Web Worker keeping Ergo NiPoPoW V2 WASM verification off the UI thread.
import { NiPoPoWV2Wasm, fetchLiveHeadersU32le, fetchLiveBlockProofBundle } from "./nipopow-v2.js";

let wasmClient = null;

self.onmessage = async (ev) => {
  const { id, type, payload } = ev.data;
  try {
    if (type === "init") {
      wasmClient = await NiPoPoWV2Wasm.load(payload.wasmBytes);
      self.postMessage({
        id,
        ok: true,
        result: { instantiateMs: wasmClient.instantiateMs, rawBytes: payload.wasmBytes.byteLength },
      });
    } else if (type === "verifyCert") {
      if (!wasmClient) throw new Error("WASM not initialized");
      const res = wasmClient.verifyCert(
        payload.certBytes,
        payload.tailBytes,
        payload.queryHeight ?? 1823986,
        payload.vkCsv ?? ""
      );
      self.postMessage({ id, ok: true, result: res });
    } else if (type === "extendTail") {
      if (!wasmClient) throw new Error("WASM not initialized");
      const res = wasmClient.extendTail(payload.checkpointJson, payload.extBytes);
      self.postMessage({ id, ok: true, result: res });
    } else if (type === "extendLiveFromNode") {
      if (!wasmClient) throw new Error("WASM not initialized");
      const { nodeUrl, checkpointJson, count } = payload;
      const ckptObj = JSON.parse(checkpointJson);
      const fromH = ckptObj.tip_height;
      const base = nodeUrl.replace(/\/+$/, "");
      const infoResp = await fetch(`${base}/info`);
      if (!infoResp.ok) throw new Error(`Node /info HTTP ${infoResp.status}`);
      const info = await infoResp.json();
      const nodeTip = info.headersHeight ?? info.fullHeight;
      if (!nodeTip || nodeTip <= fromH) {
        throw new Error(`Node tip (${nodeTip}) is not ahead of checkpoint (${fromH})`);
      }
      const targetH = count > 0 ? Math.min(fromH + count, nodeTip) : nodeTip;
      const { u32le } = await fetchLiveHeadersU32le(nodeUrl, fromH, targetH, (prog) => {
        self.postMessage({ id, progress: prog });
      });
      const res = wasmClient.extendTail(checkpointJson, u32le);
      self.postMessage({
        id,
        ok: true,
        result: { ...res, nodeTipHeight: nodeTip, wireBytes: u32le.byteLength },
      });
    } else if (type === "verifyLiveStateProof") {
      if (!wasmClient) throw new Error("WASM not initialized");
      const res = wasmClient.verifyLiveStateProof(
        payload.checkpointJson,
        payload.extBytes,
        payload.fixtureBytes
      );
      self.postMessage({ id, ok: true, result: res });
    } else if (type === "verifyLiveBlockFromNode") {
      if (!wasmClient) throw new Error("WASM not initialized");
      const { nodeUrl, checkpointJson, targetHeight, txSelector } = payload;
      const ckpt = JSON.parse(checkpointJson);
      const h = targetHeight > 0 ? targetHeight : ckpt.tip_height;
      const bundle = await fetchLiveBlockProofBundle(nodeUrl, ckpt.tip_height, h, txSelector);
      const res = wasmClient.verifyCheckpointBlockState(
        checkpointJson,
        bundle.headerChainDescU32le,
        bundle.blockProofJson
      );
      self.postMessage({
        id,
        ok: true,
        result: { ...res, tx_id: bundle.txId, tx_count: bundle.txCount },
      });
    } else {
      throw new Error(`Unknown worker action: ${type}`);
    }
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message || err) });
  }
};
