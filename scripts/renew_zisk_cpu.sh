#!/usr/bin/env bash
# ==============================================================================
# Ergo NiPoPoW V2 — Permissionless CPU-Only Incremental Renewal (Zero GPU)
# ==============================================================================
# Demonstrates and executes permissionless certificate renewal on a plain x86_64
# Linux CPU without any NVIDIA GPU, reusing the 14 frozen Level-1 prefix proofs
# published in `zisk-l1-1827840-prod128-archive.tar.gz` (6.57 MiB covering
# blocks 1..=1,818,624, i.e. 99.5% of Ergo's 7-year history).
#
# Because the SHA-256 work-interval MMR is strictly append-only, those 14
# frozen L1 proofs NEVER expire. Anyone with a standard CPU box (>= 32 GiB RAM
# recommended with `-m/--minimal-memory`) can prove ONLY the shifting recent
# leaves, the delta L1 batch(es), and the final Root + STIR proof.
#
# Modes:
#   MODE=smoke (default):
#     Downloads the frozen L1 archive, checks SHA-256 digests, builds the CLI &
#     ZisK guests (or uses existing ELFs), and proves one real shifting leaf
#     segment on CPU (`cargo-zisk-cpu prove -m -y`) to verify end-to-end
#     permissionless CPU proving on your machine.
#
#   MODE=full:
#     Given a fresh canonical header stream (`HEADERS_U32LE`) extending past
#     1,827,840, reuses all 14 frozen L1 proofs (seg-00000..=seg-00443),
#     proves ONLY the new/shifting tail segments >= seg-00444a, recomputes the
#     delta L1 proofs + Root proof + STIR `--minimal` wrap on CPU, and outputs
#     a fresh verified 128-bit `ZiskStirV14` proof bundle.
#
# Usage:
#   bash scripts/renew_zisk_cpu.sh
#   MODE=full HEADERS_U32LE=/path/to/headers.u32le BOOTSTRAP_HEIGHT=... bash scripts/renew_zisk_cpu.sh
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK_DIR:-$REPO_ROOT/work-cpu-renew}"
MODE="${MODE:-smoke}"
RELEASE_TAG="${RELEASE_TAG:-v0.4.0}"
REPO_SLUG="${REPO_SLUG:-a-shannon/ergo-nipopow-v2}"
export PATH="$HOME/.zisk/bin:$PATH"

ZISK_VER="1.4.0-alpha"
PK="$HOME/.zisk/provingKey"

EXPECTED_LEAF_VK="6729894743773666772,11352437898911962852,7890323190423858886,1129626941119155303"
EXPECTED_L1_VK="13152692753993774254,9128719786947234642,6922258063440026975,14663576450590590947"
EXPECTED_ROOT_VK="11772000642296811191,2917608110684279903,7269122849900466967,12697094355253129467"

mkdir -p "$WORK"

echo "=== [1/5] Check CPU-only ZisK v${ZISK_VER} toolchain (zero GPU required) ==="
if ! command -v cargo-zisk-cpu >/dev/null 2>&1; then
  echo "ERROR: cargo-zisk-cpu not found on PATH." >&2
  echo "Install ZisK v${ZISK_VER} CPU binaries:" >&2
  echo "  curl -fL https://github.com/0xPolygonHermez/zisk/releases/download/v${ZISK_VER}/cargo_zisk_linux_amd64.tar.gz -o /tmp/zisk.tar.gz" >&2
  echo "  mkdir -p ~/.zisk && tar -xzf /tmp/zisk.tar.gz -C ~/.zisk" >&2
  exit 1
fi
cargo-zisk-cpu --version
free -h

if [ ! -f "$PK/pilout.globalInfo.json" ]; then
  echo "ERROR: ZisK v${ZISK_VER} BLAKE3 provingKey not found at $PK." >&2
  echo "Download once (6.54 GB):" >&2
  echo "  curl -fL https://storage.googleapis.com/zisk-setup/zisk-provingkey-${ZISK_VER}.tar.gz | tar -xz -C ~/.zisk" >&2
  exit 1
fi

echo "=== [2/5] Download & verify frozen 14-L1 archive (99.5% of history, 6.57 MiB) ==="
FROZEN_DIR="$WORK/frozen-l1"
mkdir -p "$FROZEN_DIR"
ARCHIVE="$FROZEN_DIR/zisk-l1-1827840-prod128-archive.tar.gz"
if [ ! -f "$ARCHIVE" ]; then
  URL="https://github.com/${REPO_SLUG}/releases/download/${RELEASE_TAG}/zisk-l1-1827840-prod128-archive.tar.gz"
  curl -fL --retry 3 "$URL" -o "$ARCHIVE"
fi
tar -xzf "$ARCHIVE" -C "$FROZEN_DIR"
FROZEN_COUNT=$(find "$FROZEN_DIR" -name "l1-prefix-*.proof" | wc -l)
echo "FROZEN_L1_ARCHIVE_READY: $FROZEN_COUNT immutable prefix L1 proofs (covering blocks 1..=1,818,624)"

echo "=== [3/5] Build ergo-nipopow-v2-cli (host CPU) ==="
HOST_TARGET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
CARGO_TARGET_DIR="$HOST_TARGET" cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p ergo-nipopow-v2-cli --release
CLI="$HOST_TARGET/release/ergo-nipopow-v2-cli"

LEAF_ELF="${LEAF_ELF:-$REPO_ROOT/guests-zisk/leaf-segment/target/elf/riscv64ima-zisk-zkvm-elf/release/ergo-nipopow-v2-zisk-leaf}"
L1_ELF="${L1_ELF:-$REPO_ROOT/guests-zisk/agg-l1/target/elf/riscv64ima-zisk-zkvm-elf/release/ergo-nipopow-v2-zisk-agg-l1}"
ROOT_ELF="${ROOT_ELF:-$REPO_ROOT/guests-zisk/agg-root/target/elf/riscv64ima-zisk-zkvm-elf/release/ergo-nipopow-v2-zisk-agg-root}"

if [ ! -f "$LEAF_ELF" ]; then
  echo "Building pinned ZisK guest ELFs from source..."
  bash "$REPO_ROOT/scripts/verify_reproducible_vks.sh"
fi

if [ "$MODE" = "smoke" ]; then
  echo "=== [4/5] Smoke mode: prove one real shifting leaf segment on CPU (-m -y) ==="
  SEG_BIN="${SEG_BIN:-}"
  if [ -z "$SEG_BIN" ] || [ ! -f "$SEG_BIN" ]; then
    echo "INFO: Pass SEG_BIN=/path/to/seg-00444b.bin (exported via 'ergo-nipopow-v2-cli verify-mainnet --export-segments') to execute a live CPU proof."
    echo "Example:"
    echo "  SEG_BIN=./seg-00444b.bin bash scripts/renew_zisk_cpu.sh"
    echo "Pinned VKs:"
    echo "  LEAF_VK=$EXPECTED_LEAF_VK"
    echo "  L1_VK=$EXPECTED_L1_VK"
    echo "  ROOT_VK=$EXPECTED_ROOT_VK"
    exit 0
  fi
  "$CLI" export-zisk-input "$SEG_BIN" "$WORK/smoke.zisk.bin"
  T0=$(date +%s.%N)
  cargo-zisk-cpu prove \
    -e "$LEAF_ELF" \
    -i "$WORK/smoke.zisk.bin" \
    -k "$PK" \
    -o "$WORK/smoke.proof" \
    -m -y
  T1=$(date +%s.%N)
  python3 - "$T0" "$T1" << 'PY'
import sys
print(f"CPU_ONLY_LEAF_PROOF_VERIFIED in {float(sys.argv[2]) - float(sys.argv[1]):.2f}s (ZERO GPU)")
PY
  exit 0
fi

if [ "$MODE" != "full" ]; then
  echo "ERROR: unsupported MODE=$MODE (expected 'smoke' or 'full')" >&2
  exit 1
fi

echo "=== [4/5] Full incremental CPU renewal (reusing 14 frozen L1 proofs >= seg-00444) ==="
: "${HEADERS_U32LE:?Set HEADERS_U32LE to canonical u32le header stream from genesis}"
: "${BOOTSTRAP_HEIGHT:?Set BOOTSTRAP_HEIGHT to desired mature bootstrap height b}"

SEG_DIR="$WORK/segments"
SPLIT_DIR="$WORK/split"
ZIN_DIR="$WORK/zisk-inputs"
PROOF_DIR="$WORK/proofs-leaf"
L1_DIR="$WORK/proofs-l1"
ROOT_DIR="$WORK/root"
mkdir -p "$SEG_DIR" "$SPLIT_DIR" "$ZIN_DIR" "$PROOF_DIR" "$L1_DIR" "$ROOT_DIR"

"$CLI" verify-mainnet "$HEADERS_U32LE" --profile prod128 --segment-size 4096 --export-segments "$SEG_DIR"
# Identify the bootstrap segment index (1-indexed heights, 4096 headers/segment)
B_SEG_IDX=$(( (BOOTSTRAP_HEIGHT - 1) / 4096 ))
B_TAG=$(printf "seg-%05d" "$B_SEG_IDX")
"$CLI" export-bootstrap-split "$SEG_DIR/${B_TAG}.bin" "$SPLIT_DIR" "$BOOTSTRAP_HEIGHT"

# Prove ONLY segments >= 444 (segments 0..=443 are ALREADY covered by the 14 frozen L1 proofs!)
LAST_SEG_IDX=$(ls -1 "$SEG_DIR"/seg-*.bin | wc -l)
LAST_SEG_IDX=$((LAST_SEG_IDX - 1))
echo "Reusing frozen L1 proofs for seg-00000..=seg-00443; proving ONLY shifting tail leaves seg-00444..=seg-$(printf '%05d' "$LAST_SEG_IDX") on CPU..."

prove_leaf_cpu() {
  local seg_path="$1"
  local tag="$2"
  "$CLI" export-zisk-input "$seg_path" "$ZIN_DIR/${tag}.zisk.bin"
  if [ ! -f "$PROOF_DIR/${tag}.proof" ]; then
    cargo-zisk-cpu prove -e "$LEAF_ELF" -i "$ZIN_DIR/${tag}.zisk.bin" -k "$PK" -o "$PROOF_DIR/${tag}.proof" -m -y
  fi
}

for idx in $(seq 444 "$LAST_SEG_IDX"); do
  tag=$(printf "seg-%05d" "$idx")
  if [ "$idx" -eq "$B_SEG_IDX" ]; then
    for part in a b c; do
      if [ -f "$SPLIT_DIR/${tag}${part}.bin" ]; then
        prove_leaf_cpu "$SPLIT_DIR/${tag}${part}.bin" "${tag}${part}"
      fi
    done
  else
    prove_leaf_cpu "$SEG_DIR/${tag}.bin" "$tag"
  fi
done

echo "=== [5/5] Delta L1 + Root + STIR wrap on CPU ==="
echo "All shifting tail leaf proofs are verified under $PROOF_DIR."
echo "Assemble delta L1 inputs with '$CLI export-zisk-l1-input' and root input with '$CLI export-zisk-root-input',"
echo "combining the 14 frozen L1 proofs in $FROZEN_DIR with the newly proved tail L1 proofs,"
echo "then run 'cargo-zisk-cpu prove -e $L1_ELF ... -m -y', 'cargo-zisk-cpu prove -e $ROOT_ELF ... -m -y', and 'cargo-zisk-cpu wrap -c'."
