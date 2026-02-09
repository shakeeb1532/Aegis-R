#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"
VERSION="${VERSION:-dev}"

mkdir -p "${OUT_DIR}"

build_public() {
  echo "Building public binary..."
  GOFLAGS="" go build -o "${OUT_DIR}/aegisr-${VERSION}-public" ./cmd/aegisr
  echo "Built: ${OUT_DIR}/aegisr-${VERSION}-public"
}

build_private() {
  echo "Building private binary (requires private build tag)..."
  if GOFLAGS="" go list -tags private ./... >/dev/null 2>&1; then
    GOFLAGS="" go build -tags private -o "${OUT_DIR}/aegisr-${VERSION}-private" ./cmd/aegisr
    echo "Built: ${OUT_DIR}/aegisr-${VERSION}-private"
  else
    echo "Private build tag not available in this environment."
    echo "Skipped private build."
  fi
}

case "${1:-}" in
  public)
    build_public
    ;;
  private)
    build_private
    ;;
  *)
    build_public
    build_private
    ;;
esac
