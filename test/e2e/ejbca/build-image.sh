#!/usr/bin/env bash
#
# Builds the preconfigured EJBCA test image used by the cmp-issuer end-to-end suite.
#
# The upstream image cannot be configured by a Dockerfile alone, because its certification authority,
# its administrator identity and its CMP aliases only exist once the application server has started and
# the command line interface has run against it. This script therefore starts the upstream image once,
# configures it, takes the resulting state out of the container and bakes that state into a new image.
# A test run then only has to start a container.
#
# Usage:
#   test/e2e/ejbca/build-image.sh
#
# Environment:
#   EJBCA_VERSION       upstream EJBCA Community Edition tag to build from
#   EJBCA_TEST_IMAGE    image reference to produce
#   EJBCA_HOSTNAME      hostname baked into the TLS server certificate, which has to be the name the
#                       suite reaches the server through
#   EJBCA_TEST_PUSH     set to true to push the produced image
#   CONTAINER_TOOL      container command, docker by default
set -euo pipefail

EJBCA_VERSION="${EJBCA_VERSION:?set EJBCA_VERSION}"
EJBCA_TEST_IMAGE="${EJBCA_TEST_IMAGE:?set EJBCA_TEST_IMAGE}"
EJBCA_HOSTNAME="${EJBCA_HOSTNAME:?set EJBCA_HOSTNAME}"
EJBCA_TEST_PUSH="${EJBCA_TEST_PUSH:-false}"
CONTAINER_TOOL="${CONTAINER_TOOL:-docker}"
EJBCA_BASE_IMAGE="${EJBCA_BASE_IMAGE:-keyfactor/ejbca-ce:${EJBCA_VERSION}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_CONTAINER="cmp-issuer-ejbca-build-$$"
CONTEXT_DIR="$(mktemp -d)"
# The registration identity and the password protecting its exported keystore. Both live only inside
# this build, and configure.sh takes the identity name from here so the two agree.
RA_IDENTITY="cmp-issuer-ra"
RA_KEYSTORE_PASSWORD="cmp-issuer-e2e"

# Reports a step with a timestamp so a slow step is visible in the build log
log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') build-image: $*"; }

# Removes the temporary container and the build context whatever the outcome
cleanup() { "${CONTAINER_TOOL}" rm -f "${BUILD_CONTAINER}" >/dev/null 2>&1 || true; rm -rf "${CONTEXT_DIR}"; }
trap cleanup EXIT

log "pulling ${EJBCA_BASE_IMAGE}"
"${CONTAINER_TOOL}" pull "${EJBCA_BASE_IMAGE}"
baseDigest="$("${CONTAINER_TOOL}" image inspect "${EJBCA_BASE_IMAGE}" --format '{{index .RepoDigests 0}}' | cut -d@ -f2)"
log "base image digest ${baseDigest}"

log "starting a temporary container to configure"
"${CONTAINER_TOOL}" run -d --name "${BUILD_CONTAINER}" \
    -e "HTTPSERVER_HOSTNAME=${EJBCA_HOSTNAME}" \
    -e TLS_SETUP_ENABLED=true \
    -e "DATABASE_JDBC_URL=jdbc:h2:/mnt/persistent/ejbcadb;DB_CLOSE_DELAY=-1;NON_KEYWORDS=VALUE" \
    "${EJBCA_BASE_IMAGE}" >/dev/null

mkdir -p "${CONTEXT_DIR}/state"
"${CONTAINER_TOOL}" exec "${BUILD_CONTAINER}" mkdir -p /tmp/cmp-issuer-e2e
"${CONTAINER_TOOL}" cp "${SCRIPT_DIR}/configure.sh" "${BUILD_CONTAINER}:/tmp/cmp-issuer-e2e-configure.sh"
log "configuring the server"
"${CONTAINER_TOOL}" exec \
    -e "RA_IDENTITY=${RA_IDENTITY}" \
    -e "RA_KEYSTORE_PASSWORD=${RA_KEYSTORE_PASSWORD}" \
    -e EXPORT_DIR=/tmp/cmp-issuer-e2e \
    "${BUILD_CONTAINER}" bash /tmp/cmp-issuer-e2e-configure.sh

log "collecting the exported trust anchors and credentials"
"${CONTAINER_TOOL}" cp "${BUILD_CONTAINER}:/tmp/cmp-issuer-e2e/." "${CONTEXT_DIR}/state/"

# The registration identity leaves the server as a keystore. It is split here rather than inside the
# container so the image carries the certificate and key in the form the suite puts into a Secret.
log "converting the registration keystore"
openssl pkcs12 -in "${CONTEXT_DIR}/state/${RA_IDENTITY}.p12" \
    -passin "pass:${RA_KEYSTORE_PASSWORD}" -nokeys -clcerts -out "${CONTEXT_DIR}/state/ra-cert.pem"
openssl pkcs12 -in "${CONTEXT_DIR}/state/${RA_IDENTITY}.p12" \
    -passin "pass:${RA_KEYSTORE_PASSWORD}" -nocerts -nodes -out "${CONTEXT_DIR}/state/ra-key.pem"
rm -f "${CONTEXT_DIR}/state/${RA_IDENTITY}.p12"
printf '%s' "${EJBCA_HOSTNAME}" > "${CONTEXT_DIR}/state/hostname"
printf '%s' "${EJBCA_VERSION}" > "${CONTEXT_DIR}/state/ejbca-version"

# The H2 database keeps its content in memory until the connection closes, so the state is only
# complete once the application has shut down.
log "stopping the container so the database is written out"
"${CONTAINER_TOOL}" stop --time 120 "${BUILD_CONTAINER}" >/dev/null

log "taking the configured state out of the persistence volume"
"${CONTAINER_TOOL}" cp "${BUILD_CONTAINER}:/mnt/persistent/." - > "${CONTEXT_DIR}/state/persistent.tar"
if ! tar -tf "${CONTEXT_DIR}/state/persistent.tar" | grep -q '^\./ejbcadb\.mv\.db$'; then
    echo "the collected state carries no database, the configuration did not survive the shutdown" >&2
    exit 1
fi

cp "${SCRIPT_DIR}/entrypoint.sh" "${CONTEXT_DIR}/entrypoint.sh"
log "building ${EJBCA_TEST_IMAGE}"
# The provenance and bill of materials attachments that a build adds by default turn the result into a
# multiple manifest image, which the cluster loader used by the tests cannot import.
export BUILDX_NO_DEFAULT_ATTESTATIONS=1
"${CONTAINER_TOOL}" build \
    --file "${SCRIPT_DIR}/Dockerfile" \
    --build-arg "EJBCA_IMAGE=${EJBCA_BASE_IMAGE}" \
    --build-arg "EJBCA_HOSTNAME=${EJBCA_HOSTNAME}" \
    --build-arg "EJBCA_VERSION=${EJBCA_VERSION}" \
    --build-arg "EJBCA_BASE_DIGEST=${baseDigest}" \
    --tag "${EJBCA_TEST_IMAGE}" \
    "${CONTEXT_DIR}"

if [ "${EJBCA_TEST_PUSH}" = "true" ]; then
    log "pushing ${EJBCA_TEST_IMAGE}"
    "${CONTAINER_TOOL}" push "${EJBCA_TEST_IMAGE}"
fi

log "built ${EJBCA_TEST_IMAGE} from ${EJBCA_BASE_IMAGE}@${baseDigest}"
