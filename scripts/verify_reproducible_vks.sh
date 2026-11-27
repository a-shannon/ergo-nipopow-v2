#!/usr/bin/env bash
# ==============================================================================
# Ergo NiPoPoW V2 — Reproducible Verifying-Key / Program Fingerprint Audit
# ==============================================================================
# Rebuilds the three ZisK v1.4.0-alpha RV64IMA recursive guest ELFs directly
# from the committed Rust sources and pinned Cargo.lock files in `guests-zisk/`
# using deterministic `--remap-path-prefix` flags, verifies that ZERO build-host
# paths remain in the ELF binaries, and checks that `cargo-zisk setup` reproduces
# the EXACT canonical path-independent ROM roots on any x86_64 Linux machine.
#
# Note on v0.2.0 vs v0.3.0 VKs:
#   The initial v0.2.0 mainnet snapshot (n = 1,827,840) was built before
#   `--remap-path-prefix` was enabled (so `agg-l1` reproduces its v0.2.0 ROM root
#   across directories with Cargo.lock pinned, while `leaf-segment` and `agg-root`
#   retained build-host panic paths in `.rodata`). Starting in v0.3.0, this script
#   enforces path-independent deterministic builds for all future proving campaigns.
#
# No GPU required.
#
# Usage:
#   bash scripts/verify_reproducible_vks.sh
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.zisk/bin:$HOME/.cargo/bin:$PATH"
CARGO_HOME_EFF="${CARGO_HOME:-$HOME/.cargo}"
PK="${ZISK_PROVING_KEY:-$HOME/.zisk/provingKey}"

# Canonical path-independent ZisK v1.4.0-alpha ROM roots (--remap-path-prefix)
CANONICAL_LEAF_VK="6729894743773666772,11352437898911962852,7890323190423858886,1129626941119155303"
CANONICAL_L1_VK="5235618063795392434,4171709797758932508,5383424065217591923,5276006706482555221"
CANONICAL_ROOT_VK="14775302394889233081,9096538287251514228,8017293709441266280,9065878602930789588"

ZISK_BIN=""
if command -v cargo-zisk-cpu >/dev/null 2>&1; then
  ZISK_BIN="cargo-zisk-cpu"
elif command -v cargo-zisk >/dev/null 2>&1; then
  ZISK_BIN="cargo-zisk"
else
  echo "ERROR: neither cargo-zisk-cpu nor cargo-zisk found on PATH" >&2
  echo "Install ZisK v1.4.0-alpha CPU toolchain from https://github.com/0xPolygonHermez/zisk/releases/tag/v1.4.0-alpha" >&2
  exit 1
fi

if [ ! -f "$PK/pilout.globalInfo.json" ]; then
  echo "ERROR: ZisK v1.4.0-alpha provingKey not found at $PK" >&2
  exit 1
fi

echo "=== [1/4] Verify pinned Cargo.lock files & v0.2.0 source constant consistency ==="
for lock in \
  "$REPO_ROOT/guests-zisk/leaf-segment/Cargo.lock" \
  "$REPO_ROOT/guests-zisk/agg-l1/Cargo.lock" \
  "$REPO_ROOT/guests-zisk/agg-root/Cargo.lock" \
  "$REPO_ROOT/guests/leaf-segment/Cargo.lock" \
  "$REPO_ROOT/guests/agg-l1/Cargo.lock" \
  "$REPO_ROOT/guests/agg-root/Cargo.lock"; do
  if [ ! -f "$lock" ]; then
    echo "ERROR: missing pinned lockfile: $lock" >&2
    exit 1
  fi
done
grep -Fq "9110326089375293727" "$REPO_ROOT/guests-zisk/agg-l1/src/pinned_leaf.rs"
grep -Fq "5319951898812481023" "$REPO_ROOT/guests-zisk/agg-root/src/pinned_l1.rs"
grep -Fq "2061927828237341284" "$REPO_ROOT/crates/ergo-nipopow-v2-light/src/lib.rs"
echo "SOURCE_LOCKFILES_AND_PINS_OK"

build_and_check_guest() {
  local name="$1"
  local dir="$2"
  local bin_name="$3"
  local expected_vk="$4"

  echo "=== Building $name from $dir (with --remap-path-prefix) ==="
  (
    cd "$REPO_ROOT/$dir"
    RUSTFLAGS="--remap-path-prefix=$REPO_ROOT=/ergo-nipopow-v2 --remap-path-prefix=$CARGO_HOME_EFF=/cargo" \
      "$ZISK_BIN" build --release
  )
  local elf="$REPO_ROOT/$dir/target/elf/riscv64ima-zisk-zkvm-elf/release/$bin_name"
  if [ ! -f "$elf" ]; then
    echo "ERROR: expected built ELF not found at $elf" >&2
    exit 1
  fi
  if strings "$elf" | grep -Fq "$REPO_ROOT"; then
    echo "ERROR: build-host path leaked into $elf" >&2
    exit 1
  fi
  local sha
  sha=$(sha256sum "$elf" | awk '{print $1}')
  local out
  out="$("$ZISK_BIN" setup -e "$elf" -k "$PK" 2>&1)"
  local got_vk
  got_vk=$(echo "$out" | grep "Root hash:" | sed -E 's/.*\[([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)\].*/\1,\2,\3,\4/')
  echo "  ELF SHA-256 : $sha"
  echo "  Computed VK : [$got_vk]"
  echo "  Expected VK : [$expected_vk]"
  if [ "$got_vk" != "$expected_vk" ]; then
    echo "ERROR: Canonical remapped ROM root mismatch for $name!" >&2
    exit 1
  fi
  echo "  PATH_INDEPENDENT_REPRODUCIBLE_VK_MATCH: $name"
}

echo "=== [2/4] Rebuild & verify ZisK leaf guest ==="
build_and_check_guest "leaf-segment" "guests-zisk/leaf-segment" "ergo-nipopow-v2-zisk-leaf" "$CANONICAL_LEAF_VK"

echo "=== [3/4] Rebuild & verify ZisK L1 aggregator guest ==="
build_and_check_guest "agg-l1" "guests-zisk/agg-l1" "ergo-nipopow-v2-zisk-agg-l1" "$CANONICAL_L1_VK"

echo "=== [4/4] Rebuild & verify ZisK Root aggregator guest ==="
build_and_check_guest "agg-root" "guests-zisk/agg-root" "ergo-nipopow-v2-zisk-agg-root" "$CANONICAL_ROOT_VK"

echo "=== ALL_3_CANONICAL_PATH_INDEPENDENT_ZISK_VKS_REPRODUCED_BIT_FOR_BIT ==="
