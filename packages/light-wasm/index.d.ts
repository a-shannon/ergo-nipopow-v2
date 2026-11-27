export interface ErgoHeaderJson {
  version: number;
  parentId: string;
  adProofsRoot: string;
  transactionsRoot: string;
  stateRoot: string;
  timestamp: number | string;
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
  value: number | string;
  ergoTree: string;
  creationHeight: number;
  assets: Array<{ tokenId: string; amount: number | string }>;
  additionalRegisters?: Record<string, string>;
  transactionId: string;
  index: number;
}

export interface ExtractedBlockStateChanges {
  ad_proofs_hex: string;
  lookup_box_ids: string[];
  spent_box_ids: string[];
  created_boxes: Array<{ box_id: string; raw_bytes_hex: string }>;
  tx_count: number;
  tx_ids: string[];
}

export interface LiveHeadersFetchResult {
  headers: ErgoHeaderJson[];
  u32le: Uint8Array;
}

export interface LiveBlockProofBundle {
  blockId: string;
  targetHeight: number;
  txId: string | null;
  txCount: number;
  headerChainDescU32le: Uint8Array;
  blockProofJson: string;
}

export interface VerifiedColdCert {
  profile: "V2Production128";
  backend: "ZiskStirV14" | "DualZiskV14OpenVmV21";
  dual_openvm_present: boolean;
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
  spent_count: number;
  created_count: number;
  tx_merkle_verified: boolean;
  elapsedMs: number;
}

export interface CheckpointBlockStateResult {
  height: number;
  block_id: string;
  tip_height: number;
  header_chain_len: number;
  prev_state_root: string;
  next_state_root: string;
  ad_bytes: number;
  lookup_count: number;
  spent_count: number;
  created_count: number;
  tx_merkle_verified: boolean;
  elapsedMs: number;
}

export function hexToBytes(hex: string): Uint8Array;
export function bytesToHex(bytes: Uint8Array): string;
export function encodeVlqUint(value: number | bigint): Uint8Array;
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
  txSelector?: number | string
): Promise<LiveBlockProofBundle>;

export class NiPoPoWV2Wasm {
  readonly instantiateMs: number;

  static load(wasmBytes: Uint8Array | ArrayBuffer): Promise<NiPoPoWV2Wasm>;

  verifyCert(
    certBytes: Uint8Array,
    tailBytes: Uint8Array,
    queryHeight?: number,
    vkCsv?: string
  ): VerifiedColdCert;

  extendTail(checkpointJson: string, extU32leBytes: Uint8Array): ExtendedTailResult;

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
