#!/usr/bin/env bash
# ==============================================================================
# Ergo NiPoPoW V2 (V2Production128, strict 128-bit) — Cloud Multi-GPU Runner
# Launches N independent warm (zisk-coordinator + 1x zisk-worker-gpu) pairs
# (one per RTX 5090) to avoid distributed Phase3 fold+final overhead/bugs and
# achieve full linear N-GPU parallel throughput across all 449 leaves + L1 + Root.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${WORK_DIR:-$SCRIPT_DIR/work}"
FAN_IN="${FAN_IN:-32}"
BOOTSTRAP_HEIGHT=1819644
QUERY_HEIGHT=1823986

EXPECTED_LEAF_VK="9110326089375293727,2656454419186733083,1581716303455200999,11820023294815474883"
EXPECTED_L1_VK="5319951898812481023,12834882460020413992,8904808812702811473,9762453858803393301"
EXPECTED_ROOT_VK="2061927828237341284,1907988207398174607,15624447174404746195,12050011039068599532"

CLI="$SCRIPT_DIR/bin/ergo-nipopow-v2-cli"
LEAF_ELF="$SCRIPT_DIR/elfs/ergo-nipopow-v2-zisk-leaf"
L1_ELF="$SCRIPT_DIR/elfs/ergo-nipopow-v2-zisk-agg-l1"
ROOT_ELF="$SCRIPT_DIR/elfs/ergo-nipopow-v2-zisk-agg-root"
HEADERS_U32LE="$SCRIPT_DIR/prefix-1827840.u32le"

export PATH="$HOME/.zisk/bin:$PATH"
PK="$HOME/.zisk/provingKey"

NGPUS=$(nvidia-smi --query-gpu=name --format=csv,noheader | wc -l)
if [ "$NGPUS" -lt 1 ]; then
  echo "ERROR: no NVIDIA GPU detected" >&2
  exit 1
fi

SEG_DIR="$WORK/segments-4096-128"
SPLIT_DIR="$WORK/segments-split-128"
ZISK_IN_DIR="$WORK/zisk-leaf-inputs"
LEAF_PROOF_DIR="$WORK/proofs-leaf"
L1_IN_DIR="$WORK/zisk-l1-inputs"
L1_PROOF_DIR="$WORK/proofs-l1"
ROOT_DIR="$WORK/root"
LOG_DIR="$WORK/logs"
PROGRESS_JSONL="$WORK/zisk-campaign-progress.jsonl"
mkdir -p "$SEG_DIR" "$SPLIT_DIR" "$ZISK_IN_DIR" "$LEAF_PROOF_DIR" "$L1_IN_DIR" "$L1_PROOF_DIR" "$ROOT_DIR" "$LOG_DIR"

echo "=== [1/6] Ensuring all 449 V2Production128 segments & leaf inputs exist ==="
if [ ! -f "$SEG_DIR/seg-00446.bin" ]; then
  "$CLI" verify-mainnet "$HEADERS_U32LE" --profile prod128 --segment-size 4096 --export-segments "$SEG_DIR"
fi
if [ ! -f "$SPLIT_DIR/seg-00444c.bin" ]; then
  "$CLI" export-bootstrap-split "$SEG_DIR/seg-00444.bin" "$SPLIT_DIR" "$BOOTSTRAP_HEIGHT"
fi
if [ ! -f "$ZISK_IN_DIR/expected_digests.txt" ]; then
  "$CLI" export-all-zisk-inputs "$SEG_DIR" "$SPLIT_DIR" "$ZISK_IN_DIR"
fi
echo "Leaf input count: $(wc -l < "$ZISK_IN_DIR/expected_digests.txt") | Already proved: $(ls -1 "$LEAF_PROOF_DIR"/*.proof 2>/dev/null | wc -l)"

echo "=== [2/6] Launching $NGPUS independent single-GPU (coordinator + worker) pair(s) ==="
pkill -f "zisk-coordinator|zisk-worker-gpu" 2>/dev/null || true
sleep 1

PIDS=()
COORD_URLS=()
cleanup() {
  echo "Shutting down $NGPUS coordinator/worker pair(s)..."
  for p in "${PIDS[@]:-}"; do
    kill "$p" 2>/dev/null || true
  done
  sleep 1
  for p in "${PIDS[@]:-}"; do
    wait "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

for g in $(seq 0 $((NGPUS - 1))); do
  API_PORT=$((7000 + g * 10))
  CLUSTER_PORT=$((7001 + g * 10))
  METRICS_PORT=$((9090 + g))
  COORD_URLS+=("http://127.0.0.1:${API_PORT}")

  echo "Starting pair $g on GPU $g (api=$API_PORT, cluster=$CLUSTER_PORT, metrics=$METRICS_PORT)..."
  "$HOME/.zisk/bin/zisk-coordinator" \
    -a "$API_PORT" \
    --cluster-port "$CLUSTER_PORT" \
    --metrics-port "$METRICS_PORT" \
    > "$LOG_DIR/coord-$g.log" 2>&1 &
  CPID=$!
  PIDS+=("$CPID")
  sleep 1

  CUDA_VISIBLE_DEVICES="$g" "$HOME/.zisk/bin/zisk-worker-gpu" \
    -c "http://127.0.0.1:${CLUSTER_PORT}" \
    --worker-id "gpu-worker-$g" \
    -k "$PK" -l -g \
    > "$LOG_DIR/worker-$g.log" 2>&1 &
  WPID=$!
  PIDS+=("$WPID")

  # Wait sequentially so GPU 0 completes any one-time .const_gpu cache before GPU 1 starts
  for attempt in $(seq 1 180); do
    if grep -q "registered successfully" "$LOG_DIR/coord-$g.log" 2>/dev/null; then
      echo "Pair $g READY (worker-$g registered after $((attempt * 2))s)"
      break
    fi
    if ! kill -0 "$WPID" 2>/dev/null; then
      echo "ERROR: worker-$g exited during startup!" >&2
      tail -n 50 "$LOG_DIR/worker-$g.log" >&2
      exit 1
    fi
    sleep 2
  done
  if ! grep -q "registered successfully" "$LOG_DIR/coord-$g.log" 2>/dev/null; then
    echo "ERROR: pair $g timed out waiting for worker registration!" >&2
    tail -n 50 "$LOG_DIR/worker-$g.log" >&2
    exit 1
  fi
done
sleep 2

echo "=== [3/6] Uploading & setting up all 3 pinned RV64IMA ELFs on all $NGPUS pair(s) ==="
for g in $(seq 0 $((NGPUS - 1))); do
  url="${COORD_URLS[$g]}"
  echo "Setting up ELFs on pair $g ($url)..."
  for elf in "$LEAF_ELF" "$L1_ELF" "$ROOT_ELF"; do
    cargo-zisk remote upload --coordinator "$url" -e "$elf" >/dev/null
    cargo-zisk remote setup  --coordinator "$url" -e "$elf" >/dev/null
  done
done
echo "ALL_ELFS_SETUP_ON_ALL_PAIRS_OK"

verify_proof_digest() {
  local proof_file="$1"
  local expected_hex="$2"
  local minimal_flag="${3:-0}"
  cargo-zisk verify -p "$proof_file" >/dev/null
  python3 - "$proof_file" "$expected_hex" "$minimal_flag" << 'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
n = len(data) // 8
words = struct.unpack(f"<{n}Q", data[:n*8])
minimal = int(sys.argv[3])
assert words[0] == minimal, f"unexpected minimal flag {words[0]} != {minimal}"
off = 6 if minimal == 1 else 7
digest = b"".join(w.to_bytes(4, "little") for w in words[off:off+8]).hex()
assert digest == sys.argv[2], f"DIGEST MISMATCH on {sys.argv[1]}: {digest} != {sys.argv[2]}"
PY
}

run_queue_worker() {
  local gpu_idx="$1"
  local coord_url="$2"
  local stage="$3"
  local elf_path="$4"
  local in_dir="$5"
  local out_dir="$6"
  local total_count="$7"
  local queue_file="$8"
  local lock_file="$9"

  while true; do
    local line=""
    exec 9>"$lock_file"
    flock 9
    if [ -s "$queue_file" ]; then
      line=$(head -n 1 "$queue_file")
      sed -i '1d' "$queue_file"
    fi
    flock -u 9
    exec 9>&-

    if [ -z "$line" ]; then
      break
    fi

    local tag exp
    read -r tag exp <<< "$line"
    local dst="$out_dir/${tag}.proof"
    if [ -f "$dst" ]; then
      continue
    fi

    local ok=0
    local t0 t1
    t0=$(date +%s.%N)
    for try in 1 2 3; do
      if cargo-zisk remote prove --coordinator "$coord_url" \
          -e "$elf_path" \
          -i "$in_dir/${tag}.zisk.bin" \
          -o "${dst}.partial" \
          --metadata "${stage}=${tag}" >/dev/null 2>"$LOG_DIR/prove-${stage}-${tag}-try${try}.err"; then
        if verify_proof_digest "${dst}.partial" "$exp" 0; then
          mv "${dst}.partial" "$dst"
          rm -f "$LOG_DIR/prove-${stage}-${tag}-try${try}.err"
          ok=1
          break
        fi
      fi
      echo "[gpu$gpu_idx] WARN: $stage $tag attempt $try failed; retrying..." >&2
      cat "$LOG_DIR/prove-${stage}-${tag}-try${try}.err" >&2 || true
      rm -f "${dst}.partial"
      sleep 2
    done

    if [ "$ok" -ne 1 ]; then
      echo "[gpu$gpu_idx] FATAL: $stage $tag failed after 3 attempts!" >&2
      return 1
    fi

    t1=$(date +%s.%N)
    local done_cnt bytes
    done_cnt=$(ls -1 "$out_dir"/*.proof 2>/dev/null | wc -l)
    bytes=$(stat -c%s "$dst")
    python3 - "$stage" "$gpu_idx" "$tag" "$done_cnt" "$total_count" "$t0" "$t1" "$bytes" "$exp" "$PROGRESS_JSONL" << 'PY'
import json, sys, time
stage, gpu, tag, done, tot, t0, t1, b, exp, jf = sys.argv[1:]
dt = float(t1) - float(t0)
rec = {"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "stage": stage, "gpu": int(gpu), "tag": tag, "done": int(done), "total": int(tot), "wall_s": round(dt, 3), "bytes": int(b), "expected_sha256": exp}
with open(jf, "a") as f:
    f.write(json.dumps(rec) + "\n")
print(f"[{stage} {int(done):3d}/{int(tot)} gpu{gpu}] {tag} OK in {dt:.2f}s ({b} B)", flush=True)
PY
  done
}

echo "=== [4/6] Proving all 449 V2Production128 leaf segments across $NGPUS independent RTX 5090 pair(s) ==="
LEAF_QUEUE="$WORK/leaf_queue.txt"
LEAF_LOCK="$WORK/leaf_queue.lock"
: > "$LEAF_QUEUE"
while read -r tag exp; do
  if [ ! -f "$LEAF_PROOF_DIR/${tag}.proof" ]; then
    echo "$tag $exp" >> "$LEAF_QUEUE"
  fi
done < "$ZISK_IN_DIR/expected_digests.txt"
echo "Remaining leaves in queue: $(wc -l < "$LEAF_QUEUE")"

T_LEAVES_0=$(date +%s)
WPIDS=()
for g in $(seq 0 $((NGPUS - 1))); do
  run_queue_worker "$g" "${COORD_URLS[$g]}" "leaf" "$LEAF_ELF" "$ZISK_IN_DIR" "$LEAF_PROOF_DIR" 449 "$LEAF_QUEUE" "$LEAF_LOCK" &
  WPIDS+=($!)
done
for wp in "${WPIDS[@]}"; do
  wait "$wp"
done
T_LEAVES_1=$(date +%s)
LEAF_COUNT=$(ls -1 "$LEAF_PROOF_DIR"/*.proof | wc -l)
if [ "$LEAF_COUNT" -ne 449 ]; then
  echo "ERROR: expected 449 leaf proofs, found $LEAF_COUNT" >&2
  exit 1
fi
echo "ALL_449_LEAVES_PROVED_AND_VERIFIED in $((T_LEAVES_1 - T_LEAVES_0))s!"

echo "=== [5/6] Level-1 recursive aggregation (fan-in=$FAN_IN; 14 frozen prefix + tail + bridge + suffix = 17 proofs) ==="
L1_JOBS_TXT="$L1_IN_DIR/l1_jobs.txt"
: > "$L1_JOBS_TXT"

batch_idx=0
i=0
while [ "$i" -le 443 ]; do
  end=$((i + FAN_IN - 1))
  if [ "$end" -gt 443 ]; then end=443; fi
  bname=$(printf "l1-prefix-%02d" "$batch_idx")
  args=()
  for k in $(seq "$i" "$end"); do
    tag=$(printf "seg-%05d" "$k")
    args+=("$SEG_DIR/${tag}.bin" "$LEAF_PROOF_DIR/${tag}.proof")
  done
  out_line=$("$CLI" export-zisk-l1-input "$L1_IN_DIR/${bname}.zisk.bin" "${args[@]}")
  exp_sha=$(echo "$out_line" | sed -n 's/.*expected_sha256=\([0-9a-f]*\).*/\1/p')
  echo "$bname $exp_sha" >> "$L1_JOBS_TXT"
  batch_idx=$((batch_idx + 1))
  i=$((end + 1))
done
PREFIX_FROZEN_COUNT=$batch_idx

for spec in \
  "l1-prefix-tail|$SPLIT_DIR/seg-00444a.bin|$LEAF_PROOF_DIR/seg-00444a.proof" \
  "l1-bridge|$SPLIT_DIR/seg-00444b.bin|$LEAF_PROOF_DIR/seg-00444b.proof"; do
  IFS='|' read -r bname sbin prf <<< "$spec"
  out_line=$("$CLI" export-zisk-l1-input "$L1_IN_DIR/${bname}.zisk.bin" "$sbin" "$prf")
  exp_sha=$(echo "$out_line" | sed -n 's/.*expected_sha256=\([0-9a-f]*\).*/\1/p')
  echo "$bname $exp_sha" >> "$L1_JOBS_TXT"
done

out_line=$("$CLI" export-zisk-l1-input "$L1_IN_DIR/l1-suffix.zisk.bin" \
  "$SPLIT_DIR/seg-00444c.bin" "$LEAF_PROOF_DIR/seg-00444c.proof" \
  "$SEG_DIR/seg-00445.bin" "$LEAF_PROOF_DIR/seg-00445.proof" \
  "$SEG_DIR/seg-00446.bin" "$LEAF_PROOF_DIR/seg-00446.proof")
exp_sha=$(echo "$out_line" | sed -n 's/.*expected_sha256=\([0-9a-f]*\).*/\1/p')
echo "l1-suffix $exp_sha" >> "$L1_JOBS_TXT"

L1_TOTAL=$(wc -l < "$L1_JOBS_TXT")
L1_QUEUE="$WORK/l1_queue.txt"
L1_LOCK="$WORK/l1_queue.lock"
: > "$L1_QUEUE"
while read -r tag exp; do
  if [ ! -f "$L1_PROOF_DIR/${tag}.proof" ]; then
    echo "$tag $exp" >> "$L1_QUEUE"
  fi
done < "$L1_JOBS_TXT"
echo "L1 jobs total: $L1_TOTAL | Remaining in queue: $(wc -l < "$L1_QUEUE")"

T_L1_0=$(date +%s)
WPIDS=()
for g in $(seq 0 $((NGPUS - 1))); do
  run_queue_worker "$g" "${COORD_URLS[$g]}" "l1" "$L1_ELF" "$L1_IN_DIR" "$L1_PROOF_DIR" "$L1_TOTAL" "$L1_QUEUE" "$L1_LOCK" &
  WPIDS+=($!)
done
for wp in "${WPIDS[@]}"; do
  wait "$wp"
done
T_L1_1=$(date +%s)
echo "ALL_${L1_TOTAL}_L1_PROOFS_VERIFIED in $((T_L1_1 - T_L1_0))s!"

echo "=== [6/6] Level-2 Root proof (agg-root) + STIR --minimal (~243 KiB) + Result & L1 Bundles ==="
ROOT_ARGS=(--prefix)
for b in $(seq 0 $((PREFIX_FROZEN_COUNT - 1))); do
  bname=$(printf "l1-prefix-%02d" "$b")
  ROOT_ARGS+=("$L1_IN_DIR/${bname}.zisk.summary.bin" "$L1_PROOF_DIR/${bname}.proof")
done
ROOT_ARGS+=("$L1_IN_DIR/l1-prefix-tail.zisk.summary.bin" "$L1_PROOF_DIR/l1-prefix-tail.proof")
ROOT_ARGS+=(--bridge "$L1_IN_DIR/l1-bridge.zisk.summary.bin" "$L1_PROOF_DIR/l1-bridge.proof")
ROOT_ARGS+=(--suffix "$L1_IN_DIR/l1-suffix.zisk.summary.bin" "$L1_PROOF_DIR/l1-suffix.proof")

ROOT_LINE=$("$CLI" export-zisk-root-input "$ROOT_DIR/agg-root-1827840.zisk.bin" "${ROOT_ARGS[@]}")
echo "$ROOT_LINE"
ROOT_EXP=$(echo "$ROOT_LINE" | sed -n 's/.*expected_root_sha256=\([0-9a-f]*\).*/\1/p')

T_R0=$(date +%s)
cargo-zisk remote prove --coordinator "${COORD_URLS[0]}" \
  -e "$ROOT_ELF" \
  -i "$ROOT_DIR/agg-root-1827840.zisk.bin" \
  -o "$ROOT_DIR/root-1827840-prod128.zisk.proof" \
  --metadata "stage=root-1827840"
verify_proof_digest "$ROOT_DIR/root-1827840-prod128.zisk.proof" "$ROOT_EXP" 0
T_R1=$(date +%s)

cargo-zisk remote wrap --coordinator "${COORD_URLS[0]}" \
  -p "$ROOT_DIR/root-1827840-prod128.zisk.proof" \
  -c \
  -o "$ROOT_DIR/root-1827840-prod128.zisk.minimal.proof"
verify_proof_digest "$ROOT_DIR/root-1827840-prod128.zisk.minimal.proof" "$ROOT_EXP" 1
T_R2=$(date +%s)

cp "$ROOT_DIR/agg-root-1827840.zisk.stmt.bin" "$ROOT_DIR/bootstrap-statement-prod128.bin"
cat > "$ROOT_DIR/zisk-campaign-report.json" << JSON
{
  "profile": "V2Production128",
  "zisk_version": "1.4.0-alpha",
  "hash_family": "blake3",
  "gpus": $NGPUS,
  "mode": "independent-single-gpu-coordinators",
  "fan_in": $FAN_IN,
  "bootstrap_height": $BOOTSTRAP_HEIGHT,
  "query_height": $QUERY_HEIGHT,
  "expected_root_sha256": "$ROOT_EXP",
  "leaf_program_vk": [$EXPECTED_LEAF_VK],
  "l1_program_vk": [$EXPECTED_L1_VK],
  "root_program_vk": [$EXPECTED_ROOT_VK],
  "leaves_wall_s": $((T_LEAVES_1 - T_LEAVES_0)),
  "l1_wall_s": $((T_L1_1 - T_L1_0)),
  "root_prove_wall_s": $((T_R1 - T_R0)),
  "root_wrap_stir_wall_s": $((T_R2 - T_R1)),
  "root_fri_bytes": $(stat -c%s "$ROOT_DIR/root-1827840-prod128.zisk.proof"),
  "root_stir_minimal_bytes": $(stat -c%s "$ROOT_DIR/root-1827840-prod128.zisk.minimal.proof")
}
JSON

(
  cd "$ROOT_DIR"
  sha256sum root-1827840-prod128.zisk.minimal.proof root-1827840-prod128.zisk.proof bootstrap-statement-prod128.bin zisk-campaign-report.json > SHA256SUMS.txt
  tar -czf "$SCRIPT_DIR/zisk-root-1827840-prod128-result.tar.gz" \
    root-1827840-prod128.zisk.minimal.proof \
    root-1827840-prod128.zisk.proof \
    bootstrap-statement-prod128.bin \
    zisk-campaign-report.json \
    SHA256SUMS.txt
)

# Also archive the 17 L1 proofs + summaries (~7 MiB) for future incremental renewals!
(
  cd "$WORK"
  tar -czf "$SCRIPT_DIR/zisk-l1-1827840-prod128-archive.tar.gz" \
    proofs-l1 \
    zisk-l1-inputs/l1_jobs.txt \
    zisk-l1-inputs/*.summary.bin \
    zisk-campaign-progress.jsonl
)

echo "============================================================"
echo "ZISK_V14_PROD128_FULL_MAINNET_COMPLETE!"
ls -lh "$SCRIPT_DIR/zisk-root-1827840-prod128-result.tar.gz" "$SCRIPT_DIR/zisk-l1-1827840-prod128-archive.tar.gz"
cat "$ROOT_DIR/zisk-campaign-report.json"
echo "============================================================"
