#!/usr/bin/env bash
set -euo pipefail
case "${HARBOR_GATE_PRODUCT_PROFILE:?HARBOR_GATE_PRODUCT_PROFILE is required}" in
  nexus-amd64) export RUST_TARGET=x86_64-unknown-linux-gnu DEB_ARCH=amd64 ;;
  n2-riscv64) export RUST_TARGET=riscv64gc-unknown-linux-gnu DEB_ARCH=riscv64 ;;
  *) echo "error: unsupported Gate product profile" >&2; exit 2 ;;
esac
exec bash "$(dirname "${BASH_SOURCE[0]}")/build_harborgate_k3_deb.sh" "$@"
