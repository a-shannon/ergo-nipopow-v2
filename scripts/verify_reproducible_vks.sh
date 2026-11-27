#!/usr/bin/env bash
# ==============================================================================
# Ergo NiPoPoW V2 — Reproducible Verifying-Key / Program Fingerprint Audit
# ==============================================================================
# Rebuilds the three ZisK v1.4.0-alpha RV64IMA recursive guest ELFs directly
# from the committed Rust sources and pinned Cargo.lock files in `guests-zisk/`
# using deterministic `--remap-path-prefix` flags, verifies that ZERO build-host
# paths remain in the ELF binaries, and checks that `cargo-zisk setup` reproduces
# the EXACT canonical path-independent ROM roots pinned in the live v0.4.0
# mainnet Dual-Proof snapshot on any x86_64 Linux machine.
#
# If `cargo-openvm` (OpenVM v2.1.0) is also installed on PATH, this script
# additionally rebuilds `guests/leaf-segment` with `--remap-path-prefix`,
# checks zero host-path leakage, and verifies bit-for-bit `.vmexe` SHA-256
# parity with the live v0.4.0 OpenVM recursive leaf executable.
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
RUSTUP_HOME_EFF="${RUSTUP_HOME:-$HOME/.rustup}"
PK="${ZISK_PROVING_KEY:-$HOME/.zisk/provingKey}"

# Canonical path-independent ZisK v1.4.0-alpha ROM roots pinned in v0.4.0 (--remap-path-prefix)
CANONICAL_LEAF_VK="6729894743773666772,11352437898911962852,7890323190423858886,1129626941119155303"
CANONICAL_L1_VK="13152692753993774254,9128719786947234642,6922258063440026975,14663576450590590947"
CANONICAL_ROOT_VK="11772000642296811191,2917608110684279903,7269122849900466967,12697094355253129467"

# Canonical path-independent OpenVM v2.1.0 leaf .vmexe SHA-256 pinned in v0.4.0
CANONICAL_OPENVM_LEAF_VMEXE_SHA256="e9a785b199d26dbc99fa949291474aaea4cffe72b34592714e7ce26418f3de8e"

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

echo "=== [1/4] Verify pinned Cargo.lock files, v0.4.0 source pins & stage canonical build path ==="
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
grep -Fq "6729894743773666772" "$REPO_ROOT/guests-zisk/agg-l1/src/pinned_leaf.rs"
grep -Fq "13152692753993774254" "$REPO_ROOT/guests-zisk/agg-root/src/pinned_l1.rs"
grep -Fq "11772000642296811191" "$REPO_ROOT/crates/ergo-nipopow-v2-light/src/lib.rs"
echo "SOURCE_LOCKFILES_AND_PINS_OK"

# Stage into a fixed canonical path so Cargo path-dependency `-C metadata` hashes
# (which influence LLVM LTO symbol layout) are 100% identical across any clone path,
# while `--remap-path-prefix` strips 100% of host paths from the resulting binaries.
STAGE_DIR="/tmp/ergo-nipopow-v2-repro"
rm -rf "$STAGE_DIR"
trap 'rm -rf "$STAGE_DIR"' EXIT
mkdir -p "$STAGE_DIR/crates" "$STAGE_DIR/guests-zisk" "$STAGE_DIR/guests"
cp -a "$REPO_ROOT/crates/ergo-nipopow-v2-core" "$STAGE_DIR/crates/"
cp -a "$REPO_ROOT/guests-zisk/leaf-segment" "$REPO_ROOT/guests-zisk/agg-l1" "$REPO_ROOT/guests-zisk/agg-root" "$STAGE_DIR/guests-zisk/"
cp -a "$REPO_ROOT/guests/leaf-segment" "$REPO_ROOT/guests/agg-l1" "$REPO_ROOT/guests/agg-root" "$STAGE_DIR/guests/"
rm -rf "$STAGE_DIR/guests-zisk"/*/target "$STAGE_DIR/guests"/*/target

build_and_check_guest() {
  local name="$1"
  local dir="$2"
  local bin_name="$3"
  local expected_vk="$4"

  echo "=== Building $name from $STAGE_DIR/$dir (with --remap-path-prefix) ==="
  (
    cd "$STAGE_DIR/$dir"
    RUSTFLAGS="--remap-path-prefix=$STAGE_DIR=/ergo-nipopow-v2 --remap-path-prefix=$CARGO_HOME_EFF=/cargo --remap-path-prefix=$RUSTUP_HOME_EFF=/rustup" \
      "$ZISK_BIN" build --release
  )
  local elf="$STAGE_DIR/$dir/target/elf/riscv64ima-zisk-zkvm-elf/release/$bin_name"
  if [ ! -f "$elf" ]; then
    echo "ERROR: expected built ELF not found at $elf" >&2
    exit 1
  fi
  if strings "$elf" | grep -F "$STAGE_DIR" >/dev/null 2>&1 || strings "$elf" | grep -F "$CARGO_HOME_EFF" >/dev/null 2>&1; then
    echo "ERROR: build-host path leaked into $elf" >&2
    exit 1
  fi
  local sha
  sha=$(sha256sum "$elf" | awk '{print $1}')
  local out
  if ! out="$("$ZISK_BIN" setup -e "$elf" -k "$PK" 2>&1)"; then
    echo "ERROR: $ZISK_BIN setup failed for $name:" >&2
    echo "$out" >&2
    exit 1
  fi
  local got_vk=""
  if printf '%s\n' "$out" | grep -q "Root hash:"; then
    got_vk=$(printf '%s\n' "$out" | grep "Root hash:" | sed -E 's/.*\[([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)\].*/\1,\2,\3,\4/')
  else
    local hash_id
    hash_id=$(printf '%s\n' "$out" | grep "Hash ID:" | awk '{print $NF}')
    got_vk=$(python3 - "$HOME/.zisk/cache" "$hash_id" <<'PY'
import glob, os, struct, sys
matches = sorted(glob.glob(os.path.join(sys.argv[1], f"{sys.argv[2]}_*.verkey.bin")))
if not matches:
    sys.exit(1)
vals = struct.unpack("<4Q", open(matches[0], "rb").read()[:32])
print(",".join(str(v) for v in vals))
PY
)
  fi
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

if command -v cargo-openvm >/dev/null 2>&1; then
  echo "=== [Bonus] Rebuild & verify OpenVM v2.1.0 leaf guest (--remap-path-prefix) ==="
  (
    cd "$STAGE_DIR/guests/leaf-segment"
    RUSTFLAGS="--remap-path-prefix=$STAGE_DIR=/ergo-nipopow-v2 --remap-path-prefix=$CARGO_HOME_EFF=/cargo --remap-path-prefix=$RUSTUP_HOME_EFF=/rustup" \
      cargo-openvm openvm build
  )
  OVM_ELF="$STAGE_DIR/guests/leaf-segment/target/riscv32im-risc0-zkvm-elf/release/ergo-nipopow-v2-guest-leaf"
  OVM_VMEXE="$STAGE_DIR/guests/leaf-segment/openvm/release/ergo-nipopow-v2-guest-leaf.vmexe"
  if strings "$OVM_ELF" | grep -F "$STAGE_DIR" >/dev/null 2>&1 || strings "$OVM_ELF" | grep -F "$CARGO_HOME_EFF" >/dev/null 2>&1; then
    echo "ERROR: build-host path leaked into $OVM_ELF" >&2
    exit 1
  fi
  OVM_SHA=$(sha256sum "$OVM_VMEXE" | awk '{print $1}')
  echo "  OpenVM leaf .vmexe SHA-256 : $OVM_SHA"
  echo "  Expected .vmexe SHA-256    : $CANONICAL_OPENVM_LEAF_VMEXE_SHA256"
  if [ "$OVM_SHA" != "$CANONICAL_OPENVM_LEAF_VMEXE_SHA256" ]; then
    echo "ERROR: OpenVM remapped leaf .vmexe SHA-256 mismatch!" >&2
    exit 1
  fi
  echo "=== OPENVM_PATH_INDEPENDENT_LEAF_VMEXE_REPRODUCED_BIT_FOR_BIT ==="
fi
