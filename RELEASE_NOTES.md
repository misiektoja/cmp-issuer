# Release notes

All notable changes to this project are documented in this file.

## [0.2.0] - 28 Aug 2026

True CMP key update is now available for cert-manager renewals while P10CR re-enrollment remains the compatibility default. This release also introduces the repository metadata and release-download improvements.

### Certificate management

* **Renew certificates using KUR** - Set `spec.protocol.renewal` to `KUR` to renew a certificate using CMP Key Update Request. The current certificate is used to authenticate the renewal. Initial certificate requests still use P10CR. KUR has been tested with Nokia NCM 26.7, EJBCA Community Edition 9.3.7 and OpenSSL 3.6.3.
* **Use a separate renewal endpoint** - Set `spec.endpoint.renewalUrl` if your CMP server uses a different endpoint for renewals. Leave it unset if the same endpoint handles both enrollment and renewal.
* **Existing behavior stays the default** - Existing issuers continue to renew certificates using P10CR unless KUR is explicitly enabled. KUR requests never silently fall back to P10CR.
* **Choose how strictly responses are validated** - `spec.protocol.validationProfile` defaults to `Interoperable` for compatibility with a wider range of CMP servers. Use `RFC9483` for stricter RFC 9483 validation. Individual validation settings are also available when a server needs a custom combination.

### Security and reliability

* **Only use keys that belong to the certificate being renewed** - KUR checks that the certificate, issuer and Secrets all belong to the expected cert-manager resources before accessing private keys. P10CR continues to work without reading workload private keys.
* **Stop safely if keys change during renewal** - If a certificate or key Secret changes while a renewal is in progress, the transaction is stopped before sending more requests to the CMP server.
* **Catch invalid KUR requests before contacting the CA** - KUR checks that the current certificate is still valid, the keys match and the certificate identity has not unexpectedly changed before sending the request.

### Project maintenance

* **Know where to get help** - `SUPPORT.md` explains where to ask questions, report bugs, request features and privately report security issues.
* **Consistent repository formatting** - `.editorconfig` and optional pre-commit hooks keep files consistently formatted and catch common mistakes such as accidentally committing private keys.
* **Verify release downloads** - Releases include source archives, SHA-256 checksums and GitHub build provenance so downloaded artifacts can be verified. Both signed provenance bundles are attached to the release itself, `cmp-issuer-<version>.intoto.jsonl` for the installer, chart, SBOM, air-gapped bundle and source archives plus `cmp-issuer-<version>-provenance.sigstore.json` for the image, so `gh attestation verify --bundle` works from the release page without calling the GitHub attestations API.

## [0.1.0] - 22 Aug 2026

The first release of **cmp-issuer**, a vendor-neutral cert-manager external issuer that speaks CMPv2 directly to a certificate authority.

Point a cert-manager `Certificate` at a `CMPIssuer` or `CMPClusterIssuer` and cert-manager generates the private key and the PKCS #10 request, cmp-issuer enrolls it over CMP as a **P10CR** and the issued certificate is written to the usual TLS Secret.

This release was tested with **Nokia NCM 26.7** and **EJBCA Community Edition 9.3.7** on Kubernetes v1.34 to v1.36 with cert-manager v1.19 to v1.21.

Every CMP message is authenticated in both directions, with a shared secret or a certificate signature, over HTTP or HTTPS.

The API is currently `v1alpha1`, so it may change before a stable release.

### Certificate management

* **Issue certificates through CMPv2** - Use a `CMPIssuer` within one namespace or a `CMPClusterIssuer` across the cluster. cert-manager creates the private key and stores the issued certificate in the usual TLS Secret. See [enrollment](https://misiektoja.github.io/cmp-issuer/guide/enrollment/).
* **Renew certificates automatically** - cert-manager renewals use a new P10CR enrollment and work with either private key rotation setting. This is re-enrollment rather than a CMP Key Update Request, so the CA profile must allow the same identity to enroll again. See [renewal](https://misiektoja.github.io/cmp-issuer/guide/renewal-and-kur/).
* **Use shared-secret or certificate authentication** - Every CMP request and response must be protected with PasswordBasedMac or a certificate signature. Both HTTP and HTTPS endpoints are supported. See [message protection](https://misiektoja.github.io/cmp-issuer/guide/message-protection/).
* **Handle slow or manually approved requests** - cmp-issuer waits and polls when the CA cannot issue immediately. It also retries temporary server errors and resumes unfinished requests after a controller restart. See [transaction recovery](https://misiektoja.github.io/cmp-issuer/guide/transaction-recovery/).

### Security and reliability

* **Workload private keys stay with cert-manager** - cmp-issuer forwards the signed certificate request and never reads the private key.
* **Credentials stay within approved namespaces** - The controller has no cluster-wide Secret access. You choose which namespaces it can read during installation. See [Secret access](https://misiektoja.github.io/cmp-issuer/operations/secret-access/).
* **Responses are checked before certificates are stored** - cmp-issuer verifies the sender, message protection, transaction details, public key and certificate chain. By default it also rejects certificates when the CA changes the requested identity.
* **Connections can be locked down** - HTTPS can use the system trust store or a custom CA. Timeouts and response-size limits are configurable while redirects are always refused. See [transport](https://misiektoja.github.io/cmp-issuer/guide/transport/).
* **Release artifacts are inspectable** - Images are available for `linux/amd64` and `linux/arm64` with build provenance and a CycloneDX bill of materials. See [provenance](https://misiektoja.github.io/cmp-issuer/provenance/).

### Installation and operations

* **Choose the installation method that fits your environment** - Install with Helm, a single Kubernetes manifest or an air-gapped bundle. The Helm chart includes the CRDs and keeps them when the chart is uninstalled to protect existing issuer and transaction resources. See [installation](https://misiektoja.github.io/cmp-issuer/installation/).
* **Monitor enrollment from logs and Prometheus** - Logs summarize issued certificates and explain failed or delayed requests. Metrics cover enrollment counts, duration, failures, polling and confirmation with renewals tracked separately. See [metrics](https://misiektoja.github.io/cmp-issuer/operations/metrics/).

### Known limitations

* **Enrollment uses P10CR only** - CRMF enrollment, CMP Key Update Request, PBMAC1, CMPv3, CMP revocation and mutual TLS are not yet supported. Kubernetes CSR signing is not supported by design. See the [support matrix](https://misiektoja.github.io/cmp-issuer/support-matrix/).
* **The CA chooses certificate lifetime** - `Certificate.spec.duration` is not sent because PKCS #10 requests do not include a validity period.
* **A lost successful response may leave an unused certificate at the CA** - cmp-issuer avoids repeating the same transaction, but the tested servers do not return a certificate again after its response is lost. cert-manager must start a new enrollment.
* **Completed transaction records remain visible** - They are kept until the related `CertificateRequest` is removed so a restart cannot accidentally enroll again.
* **Ready does not test the endpoint** - Issuer readiness checks configuration only. An incorrect or unavailable URL appears when the first certificate is requested. Endpoint failover is not supported.
* **Compatibility depends on the CA profile** - CMP servers expose different options, so servers beyond the tested Nokia NCM and EJBCA versions may need additional setup. Review the full [known limitations](https://misiektoja.github.io/cmp-issuer/known-limitations/) before deployment.
