#!/bin/sh

DOCKER="docker"

${DOCKER} build -t pdu-test - <<'EOF'
FROM ubuntu:focal
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
VOLUME /usr/local/src/pdu
WORKDIR /usr/local/src/pdu
SHELL ["/bin/bash", "-eu", "-o", "pipefail", "-c"]
RUN \
  export DEBIAN_FRONTEND=noninteractive; \
  apt-get -q update; \
  apt-get -q install -y curl build-essential linux-headers-generic pkg-config binutils-dev libunwind-dev libpcap-dev tshark; \
  apt-get -q clean autoclean;
RUN \
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable; \
  source $HOME/.cargo/env; \
  cargo install honggfuzz;
ENTRYPOINT \
  source $HOME/.cargo/env; \
  cargo test --verbose
EOF

${DOCKER} run --init --rm -v "$(pwd):/usr/local/src/pdu" pdu-test
