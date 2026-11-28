export const MAX_CERT_COMPRESSED_BYTES: number;
export const MAX_TAIL_COMPRESSED_BYTES: number;
export const MAX_WASM_BYTES: number;
export const MAX_NODE_JSON_BYTES: number;
export const PROD128_MIN_CONFIRMATIONS: number;

export interface ErgoHeaderJson {
  id?: string;
  version: number;
  parentId: string;
  adProofsRoot: string;
  transactionsRoot: string;
  stateRoot: string;
  timestamp: number | string | bigint;
  extensionHash: string;
  nBits: number;
  height: number;
  votes: string;
  unparsedBytes?: string;
  powSolutions: {
    pk: string;
    n: string;
  };
}

export interface ErgoBoxJson {
  boxId: string;
  value: number | string | bigint;
  ergoTree: string;
  creationHeight: number;
  assets: Array<{ tokenId: string; amount: number | string | bigint }>;
  additionalRegisters?: Record<string, string>;
  transactionId: string;
  index: number;
}

export interface ExtractedBlockStateChanges {
  ad_proofs_hex: string;
  lookup_box_ids: string[];
  spent_box_ids: string[];
  created_boxes: Array<{ box_id: string; raw_bytes_hex: string }>;
  node_reported_tx_count: number;
  tx_ids: string[];
}

export interface LiveHeadersFetchResult {
  headers: ErgoHeaderJson[];
  u32le: Uint8Array;
}

export interface LiveBlockProofBundle {
  blockId: string;
  targetHeight: number;
  requestedTxId: string | null;
  nodeReportedTxCount: number;
  headerChainDescU32le: Uint8Array;
  blockProofJson: string;
}

export interface VerifiedColdCert {
  profile: "V2Production128";
  backend: "ZiskStirV14" | "DualZiskV14OpenVmV21";
  verified_proof: string;
  dual_openvm_present: boolean;
  openvm_half_verified: false;
  query_height: number;
  tip_height: number;
  query_id: string;
  query_state_root: string;
  audit_draws: number;
  checkpoint_json: string;
  elapsedMs: number;
}

export interface ExtendedTailResult {
  headers_verified: number;
  prev_tip_height: number;
  tip_height: number;
  tip_id: string;
  tip_state_root: string;
  checkpoint_json: string;
  elapsedMs: number;
}

export interface LiveStateProofResult {
  live_height: number;
  tip_height: number;
  prev_state_root: string;
  next_state_root: string;
  ad_bytes: number;
  lookup_count: number;
  spent_count: number;
  created_count: number;
  tx_merkle_verified: boolean;
  verified_tx_id: string;
  elapsedMs: number;
}

export interface CheckpointBlockStateResult {
  height: number;
  block_id: string;
  tip_height: number;
  confirmations: number;
  confirmed_k0: boolean;
  header_chain_len: number;
  prev_state_root: string;
  next_state_root: string;
  ad_bytes: number;
  lookup_count: number;
  spent_count: number;
  created_count: number;
  tx_merkle_verified: boolean;
  verified_tx_id: string | null;
  elapsedMs: number;
}

export function hexToBytes(hex: string): Uint8Array;
export function bytesToHex(bytes: Uint8Array): string;
export function parseJsonLosslessInts(text: string): unknown;
export function fetchBoundedBytes(url: string, maxBytes: number, timeoutMs?: number): Promise<Uint8Array>;
export function encodeVlqUint(value: number | bigint | string): Uint8Array;
export function encodeErgoHeaderJson(header: ErgoHeaderJson): Uint8Array;
export function encodeU32leStream(headers: ErgoHeaderJson[]): Uint8Array;
export function encodeErgoBoxJson(output: ErgoBoxJson): Uint8Array;
export function extractBlockStateChanges(blockJson: unknown): ExtractedBlockStateChanges;

export function fetchLiveHeadersU32le(
  nodeUrl: string,
  fromHeightExclusive: number,
  toHeightInclusive: number,
  onProgress?: ((p: { fetched: number; tipHeight: number; targetHeight: number }) => void) | null
): Promise<LiveHeadersFetchResult>;

export function fetchLiveBlockProofBundle(
  nodeUrl: string,
  checkpointTipHeight: number,
  targetHeight: number,
  txSelector?: number | string,
  minConfirmations?: number
): Promise<LiveBlockProofBundle>;

export class NiPoPoWV2Wasm {
  readonly instantiateMs: number;

  private constructor();

  static load(wasmBytes: Uint8Array | ArrayBuffer): Promise<NiPoPoWV2Wasm>;

  verifyCert(
    certBytes: Uint8Array,
    tailBytes: Uint8Array,
    queryHeight?: number,
    vkCsv?: string
  ): VerifiedColdCert;

  extendTail(
    checkpointJson: string,
    extU32leBytes: Uint8Array,
    nowMs?: number
  ): ExtendedTailResult;

  verifyLiveStateProof(
    checkpointJson: string,
    extU32leBytes: Uint8Array,
    fixtureJsonBytes: string | Uint8Array
  ): LiveStateProofResult;

  verifyCheckpointBlockState(
    checkpointJson: string,
    headerChainDescU32le: Uint8Array,
    blockProofJson: string | Uint8Array
  ): CheckpointBlockStateResult;
}
