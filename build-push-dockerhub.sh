#!/bin/bash
# build-push-dockerhub.sh — Build and push a MULTI-ARCH (amd64 + arm64)
# image for kasten-alerting to Docker Hub, using buildx/QEMU so one build
# produces a single tag that runs natively on either architecture.
#
# Prerequisites:
#   - Docker Desktop (or another buildx-capable Docker install) running
#   - docker login (to Docker Hub, as DOCKERHUB_USER)
#
# Usage:
#   DOCKERHUB_USER=<user> ./build-push-dockerhub.sh [tag]
set -euo pipefail

: "${DOCKERHUB_USER:?Set DOCKERHUB_USER to your Docker Hub username, e.g. DOCKERHUB_USER=cpouthier ./build-push-dockerhub.sh}"

IMAGE="docker.io/${DOCKERHUB_USER}/kasten-alerting"
TAG="${1:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BUILDER_NAME="kasten-alerting-builder"
ROOT="$(cd "$(dirname "$0")" && pwd)"

if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
  echo "==> Creating buildx builder '${BUILDER_NAME}' (docker-container driver, needed for multi-arch)..."
  docker buildx create --name "${BUILDER_NAME}" --driver docker-container --bootstrap
fi

echo "==> Building + pushing ${IMAGE}:${TAG} for ${PLATFORMS}..."
docker buildx build \
  --builder "${BUILDER_NAME}" \
  --platform "${PLATFORMS}" \
  -t "${IMAGE}:${TAG}" \
  --push \
  "${ROOT}"

echo "==> Published: ${IMAGE}:${TAG}"
echo
echo "==> Install/upgrade with the Helm chart:"
echo "    helm upgrade --install kasten-alerting ./helm/kasten-alerting \\"
echo "      --namespace kasten-alerting --create-namespace \\"
echo "      --set image.repository=${DOCKERHUB_USER}/kasten-alerting \\"
echo "      --set image.tag=${TAG} \\"
echo "      --set storageClass=<your-storage-class>"
