#!/bin/sh

if [ "clean" = "$1" ]; then
  echo $(pwd)/fuzz/hfuzz_target
  rm -rf $(pwd)/fuzz/hfuzz_target
  for FILE in $(pwd)/fuzz/hfuzz_workspace/*/*.*; do
    echo $FILE
    rm -f $FILE
  done
  exit
fi

DOCKER="docker"

${DOCKER} build -t pdu-fuzz - <<'EOF'
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
  mkdir -p /tmp/honggfuzz/$FUZZ_TARGET; \
  source $HOME/.cargo/env; \
  cd ./fuzz; \
  RUSTFLAGS="-C link-dead-code" HFUZZ_RUN_ARGS="-t 5 -T --output /tmp/honggfuzz/$FUZZ_TARGET" cargo hfuzz run $FUZZ_TARGET
EOF

if [ -z "$1" ]; then
  echo "Usage: fuzz.sh [ clean | ethernet | arp | ipv4 | ipv6 | tcp | udp | icmp | gre ]"
fi

${DOCKER} run --init --rm -v "$(pwd):/usr/local/src/pdu" -e FUZZ_TARGET=$1 pdu-fuzz
