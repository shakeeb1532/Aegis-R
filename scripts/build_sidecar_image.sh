#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
BIN="${BUILD_DIR}/aman"
IMAGE_TAG="${IMAGE_TAG:-aman-sidecar:pilot}"
OUT_TAR="${OUT_TAR:-${ROOT_DIR}/out/aman-sidecar_pilot.tar}"

mkdir -p "${BUILD_DIR}"
mkdir -p "$(dirname "${OUT_TAR}")"

echo "Building linux binary..."
GOOS=linux GOARCH=amd64 go build -o "${BIN}" ./cmd/aman

echo "Building sidecar image..."
cp "${BIN}" "${ROOT_DIR}/aman"
docker build -f deploy/sidecar/Dockerfile -t "${IMAGE_TAG}" "${ROOT_DIR}"
rm -f "${ROOT_DIR}/aman"

echo "Saving image to ${OUT_TAR}..."
docker save "${IMAGE_TAG}" -o "${OUT_TAR}"
echo "Done."
