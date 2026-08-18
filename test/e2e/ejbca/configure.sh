#!/usr/bin/env bash
#
# Configures a freshly started EJBCA Community Edition container for the cmp-issuer e2e suite and
# writes the credentials the suite needs into an export directory.
#
# This runs inside the container, once, while the test image is being built. Nothing here runs during
# a test run, which is the whole point of baking the result into an image.
#
# The CMP aliases are configured in RA mode so that every enrollment creates or updates the end entity
# on the server side. Client mode leaves an end entity in status GENERATED after issuance and refuses
# the next request until the status is reset, which makes a repeatable suite depend on an extra
# administrative call before every enrollment.
#
# References:
#   EJBCA command line interface: https://docs.keyfactor.com/ejbca/latest/command-line-interfaces
#   CMP alias fields: https://docs.keyfactor.com/ejbca/latest/cmp-configuration
set -euo pipefail

EJBCA_CLI=/opt/keyfactor/bin/ejbca.sh

# Names the suite also knows. Changing one here means changing it in test/e2e/ejbca_test.go as well.
ISSUING_CA_NAME="${ISSUING_CA_NAME:-CmpIssuerTestCA}"
ISSUING_CA_DN="${ISSUING_CA_DN:-CN=cmp-issuer test CA,O=cmp-issuer}"
PBM_ALIAS="${PBM_ALIAS:-cmpissuerpbm}"
SIGNATURE_ALIAS="${SIGNATURE_ALIAS:-cmpissuersig}"
PBM_REFERENCE="${PBM_REFERENCE:-cmp-issuer-e2e}"
# A throwaway value published inside a public test image. It authenticates nothing but a test CA that
# issues from a key generated in the same image, so it is a fixture rather than a credential.
PBM_SECRET="${PBM_SECRET:-cmp-issuer-e2e-not-a-real-secret}"
RA_IDENTITY="${RA_IDENTITY:-cmp-issuer-ra}"
RA_IDENTITY_DN="${RA_IDENTITY_DN:-CN=cmp-issuer-ra,O=cmp-issuer}"
RA_KEYSTORE_PASSWORD="${RA_KEYSTORE_PASSWORD:-cmp-issuer-e2e}"
EXPORT_DIR="${EXPORT_DIR:-/tmp/cmp-issuer-e2e}"

# Reports a step with a timestamp so a slow build step is visible in the log
log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') configure: $*"; }

# Runs an EJBCA command and keeps only its message text out of the server log format
ejbca() { "${EJBCA_CLI}" "$@" 2>&1 | sed 's/.*(main) //'; }

log "waiting for the application to answer its health check"
until curl -sf -k https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth >/dev/null 2>&1; do
    sleep 5
done
log "application is ready"

# A dedicated issuing CA keeps the CMP response trust anchor separate from the TLS trust anchor. The
# container generates its own server certificate from ManagementCA, so pointing the aliases at a second
# CA is what lets the suite prove that cmp-issuer keeps the two trust decisions apart.
log "creating the issuing CA ${ISSUING_CA_NAME}"
ejbca ca init \
    --caname "${ISSUING_CA_NAME}" \
    --dn "${ISSUING_CA_DN}" \
    --tokenType soft \
    --tokenPass foo123 \
    --keytype RSA \
    --keyspec 3072 \
    -s SHA256WithRSA \
    -v 3652 \
    --policy null \
    -type x509

# The identity that protects a signature-protected request. EJBCA verifies that the certificate was
# issued by the CA named in authenticationparameters and that its holder may register end entities,
# so the identity is also added to the administrator role.
log "creating the registration identity ${RA_IDENTITY}"
ejbca ra addendentity \
    --username "${RA_IDENTITY}" \
    --dn "${RA_IDENTITY_DN}" \
    --caname ManagementCA \
    --type 1 \
    --token P12 \
    --password "${RA_KEYSTORE_PASSWORD}"
ejbca ra setclearpwd --username "${RA_IDENTITY}" --password "${RA_KEYSTORE_PASSWORD}"
ejbca batch --username "${RA_IDENTITY}" -dir "${EXPORT_DIR}"
ejbca roles addrolemember \
    --role "Super Administrator Role" \
    --caname ManagementCA \
    --with "CertificateAuthenticationToken:WITH_COMMONNAME" \
    --value "${RA_IDENTITY}"

# Configures one CMP alias in RA mode, differing only in how a request is authenticated
configure_alias() {
    local alias="$1" module="$2" parameters="$3"
    log "configuring the CMP alias ${alias}"
    ejbca config cmp addalias --alias "${alias}"
    # operationmode ra: EJBCA registers the end entity itself from the request, so a repeated
    #   enrollment of the same subject succeeds instead of being refused as already generated.
    # ra.namegenerationscheme DN with ra.namegenerationparameters CN: the end entity name is taken
    #   from the common name of the certification request.
    # responseprotection signature: responses are signed by the issuing CA, which is what
    #   spec.cmpTrust.caSecretRef pins on the client side.
    # allowupdatewithsamekey true: a renewal that reuses the key is accepted, so the suite can
    #   exercise both private key rotation policies.
    local setting
    for setting in \
        "operationmode ra" \
        "authenticationmodule ${module}" \
        "authenticationparameters ${parameters}" \
        "ra.namegenerationscheme DN" \
        "ra.namegenerationparameters CN" \
        "ra.caname ${ISSUING_CA_NAME}" \
        "ra.endentityprofile EMPTY" \
        "ra.certificateprofile ENDUSER" \
        "responseprotection signature" \
        "allowupdatewithsamekey true"; do
        ejbca config cmp updatealias --alias "${alias}" \
            --key "${setting%% *}" --value "${setting#* }"
    done
}

configure_alias "${PBM_ALIAS}" HMAC "${PBM_SECRET}"
configure_alias "${SIGNATURE_ALIAS}" EndEntityCertificate ManagementCA

log "exporting the trust anchors and the alias settings"
ejbca ca getcacert --caname "${ISSUING_CA_NAME}" -f /dev/stdout \
    | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "${EXPORT_DIR}/cmp-ca.pem"
ejbca ca getcacert --caname ManagementCA -f /dev/stdout \
    | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "${EXPORT_DIR}/management-ca.pem"

# The suite reads these rather than repeating the values, so a change here reaches the tests with the
# image instead of having to be mirrored by hand.
printf '%s' "${PBM_REFERENCE}" > "${EXPORT_DIR}/pbm-reference"
printf '%s' "${PBM_SECRET}" > "${EXPORT_DIR}/pbm-secret"
printf '%s' "${PBM_ALIAS}" > "${EXPORT_DIR}/pbm-alias"
printf '%s' "${SIGNATURE_ALIAS}" > "${EXPORT_DIR}/signature-alias"

# The CMP recipient is the subject of the issuing CA certificate, so the suite reads it from
# cmp-ca.pem rather than from a value that could drift away from the certificate it names.

log "configuration complete"
