#!/usr/bin/env bash
# ============================================================
# ULPF Air-Gapped Offline Build Script
# Run on an internet-connected machine to create a portable image bundle.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_TAR="${SCRIPT_DIR}/ulpf-airgap-images.tar"
IMAGES_LIST="${SCRIPT_DIR}/ulpf-airgap-images.txt"

echo "============================================================"
echo "ULPF Air-Gapped Offline Build"
echo "============================================================"
echo "Building all images from docker-compose.airgap.yml..."
echo ""

# Build all images
docker compose -f "${SCRIPT_DIR}/docker-compose.airgap.yml" build --parallel

echo ""
echo "Saving image list..."
docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "ulpf|cp-zookeeper|cp-kafka|minio/minio|opensearchproject/opensearch|postgres|nginx|node" | sort -u > "${IMAGES_LIST}"

echo "Images to be bundled:"
cat "${IMAGES_LIST}"

echo ""
echo "Saving images to ${OUTPUT_TAR}..."
docker save -o "${OUTPUT_TAR}" $(cat "${IMAGES_LIST}")

echo ""
echo "============================================================"
echo "Build complete!"
echo "============================================================"
echo "Output: ${OUTPUT_TAR}"
echo "Image list: ${IMAGES_LIST}"
echo ""
echo "To deploy on air-gapped machine:"
echo "  1. Transfer ${OUTPUT_TAR} and ${IMAGES_LIST} to target machine"
echo "  2. Run: docker load -i ${OUTPUT_TAR}"
echo "  3. Copy docker-compose.airgap.yml and .env to target machine"
echo "  4. Run: docker compose -f docker-compose.airgap.yml up -d"
echo "============================================================"