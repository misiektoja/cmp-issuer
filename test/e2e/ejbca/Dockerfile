# EJBCA Community Edition with a CMP configuration for the cmp-issuer end-to-end suite already applied.
#
# The upstream image generates its certification authority, its administrator identity and its TLS
# keystore on first start, and every CMP alias then has to be created over the command line interface.
# Doing that once here, at image build time, is what keeps a test run down to the container start.
#
# Build this with test/e2e/ejbca/build-image.sh, which produces the build context this file expects.
# It is not buildable on its own, because the state it copies in can only be produced by running the
# upstream image and configuring it.
ARG EJBCA_IMAGE=keyfactor/ejbca-ce:9.3.7
FROM ${EJBCA_IMAGE}

# The hostname decides the subject and the subject alternative name of the TLS server certificate that
# the upstream start script issues from ManagementCA, and it selects the stored keystore on every later
# start. It is baked in so that the certificate matches the Kubernetes Service the suite reaches it
# through, which is what lets the suite verify the certificate instead of skipping verification.
ARG EJBCA_HOSTNAME
ENV HTTPSERVER_HOSTNAME=${EJBCA_HOSTNAME}

# true creates ManagementCA and an administrator identity on first start. The default, simple, leaves
# the administration interface open instead, and produces no certification authority to issue from.
ENV TLS_SETUP_ENABLED=true

# The archive of the configured state, the trust anchors and the registration credential the suite
# turns into Kubernetes Secrets.
COPY --chown=10001:0 state/ /opt/keyfactor/cmp-issuer-e2e/
COPY --chown=10001:0 entrypoint.sh /opt/keyfactor/cmp-issuer-e2e/entrypoint.sh

ARG EJBCA_VERSION
ARG EJBCA_BASE_DIGEST
LABEL org.opencontainers.image.title="cmp-issuer EJBCA test server" \
      org.opencontainers.image.description="EJBCA Community Edition preconfigured for the cmp-issuer end-to-end suite" \
      org.opencontainers.image.source="https://github.com/misiektoja/cmp-issuer" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.cmp-issuer.ejbca.version="${EJBCA_VERSION}" \
      io.cmp-issuer.ejbca.base-digest="${EJBCA_BASE_DIGEST}" \
      io.cmp-issuer.ejbca.hostname="${EJBCA_HOSTNAME}"

CMD ["/opt/keyfactor/cmp-issuer-e2e/entrypoint.sh"]
