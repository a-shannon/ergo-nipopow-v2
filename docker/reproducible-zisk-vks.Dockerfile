# ==============================================================================
# Ergo NiPoPoW V2 — Pinned Reproducible Guest Build Container (ZisK v1.4.0-alpha)
# ==============================================================================
# Builds all three ZisK v1.4.0-alpha RV64IMA recursive guests from public Rust
# sources and committed Cargo.lock files under deterministic `--remap-path-prefix`
# flags, verifying zero host-path leakage and bit-for-bit ROM-root parity.
#
# Usage:
#   docker build -f docker/reproducible-zisk-vks.Dockerfile -t ergo-nipopow-v2-repro .
#   docker run --rm -v ~/.zisk/provingKey:/root/.zisk/provingKey:ro ergo-nipopow-v2-repro
# ==============================================================================

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG ZISK_VER=1.4.0-alpha

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    build-essential \
    clang \
    libclang-dev \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    libsodium-dev \
    libomp5 \
    nasm \
    openmpi-bin \
    libopenmpi-dev \
    python3 \
    binutils \
  && rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/cargo \
    RUSTUP_HOME=/rustup \
    PATH="/root/.zisk/bin:/cargo/bin:${PATH}"

# Install pinned ZisK v1.4.0-alpha CPU toolchain & compiler
RUN mkdir -p /root/.zisk \
  && curl -fL --retry 3 \
     "https://github.com/0xPolygonHermez/zisk/releases/download/v${ZISK_VER}/cargo_zisk_linux_amd64.tar.gz" \
     -o /tmp/zisk.tar.gz \
  && tar -xzf /tmp/zisk.tar.gz -C /root/.zisk \
  && rm -f /tmp/zisk.tar.gz \
  && ln -sf /root/.zisk/bin/cargo-zisk-cpu /root/.zisk/bin/cargo-zisk \
  && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91.1 \
  && /root/.zisk/bin/cargo-zisk-cpu --version \
  && /root/.zisk/bin/cargo-zisk-cpu toolchain install

WORKDIR /ergo-nipopow-v2
COPY crates/ergo-nipopow-v2-core ./crates/ergo-nipopow-v2-core
COPY guests-zisk ./guests-zisk
COPY guests ./guests
COPY crates/ergo-nipopow-v2-light/src/lib.rs ./crates/ergo-nipopow-v2-light/src/lib.rs
COPY scripts/verify_reproducible_vks.sh ./scripts/verify_reproducible_vks.sh

CMD ["bash", "/ergo-nipopow-v2/scripts/verify_reproducible_vks.sh"]
