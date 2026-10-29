# Release notes

All notable changes to this project are documented in this file.

## [0.4.1] - 29 Oct 2026

This release labels each enrollment log line as an enrollment or a renewal and adds the cert-manager certificate revision and the CMP operation.

### Improvements

* **Enrollment log lines say whether they are an enrollment or a renewal** - Every enrollment line carries `lifecycle`, which is `enrollment` for the first certificate and `renewal` for a renewal, the same values as the `operation` metric label. It also carries `certificateRevision`, the cert-manager revision the request issues. The `Issued certificate` line names the CMP request that obtained the certificate as `operation`: `P10CR`, `IR` or `KUR`. A `CertificateRequest` created by hand counts as an enrollment and has no `certificateRevision`. See [what the log contains](https://misiektoja.github.io/cmp-issuer/operations/troubleshooting/#what-the-log-contains).

## [0.4.0] - 27 Oct 2026

This release adds **IR** initial enrollment, a requested validity for IR and KUR and a KUR fallback for a missing or expired certificate. It stops a KUR renewal loop on CAs that keep the old validity and checks recorded transaction chains against CMP trust before reuse.

### Certificate management

* **Enroll with IR** - Set `spec.protocol.initialEnrollment` to `IR` to send a CRMF Initialization Request. The key cert-manager staged for the `Certificate` signs proof of possession. IR needs a `CertificateRequest` created for a `Certificate`. A `CMPClusterIssuer` using IR needs the same Secret RoleBinding in each workload namespace as KUR. When `spec.protocol.renewal` is omitted, an IR issuer renews with KUR and a P10CR issuer with P10CR. Issuers created by earlier releases keep `renewal: P10CR`. Tested with Nokia NCM 26.7, EJBCA Community Edition 9.3.7 and OpenSSL 3.6.5.
* **Ask for a validity period** - `spec.protocol.requestedValidity: Duration` asks in each IR and KUR for a `notAfter` of the transaction start plus `Certificate.spec.duration`. The default `Omit` leaves the validity to the CA. NCM may answer `grantedWithMods`, which the default `grantedModifications: Reject` refuses. See [requested validity](https://misiektoja.github.io/cmp-issuer/guide/enrollment/#requested-validity).
* **Fall back when the current certificate is missing or expired** - With `spec.protocol.renewalFallback: InitialEnrollment` a KUR renewal whose `Certificate` Secret is deleted or holds no certificate or an expired one is sent as the `initialEnrollment` operation to `endpoint.url`. The controller records a `RenewalFallback` Warning Event. The default `None` keeps KUR. Tested after a deleted Secret with Nokia NCM 26.7 and EJBCA Community Edition 9.3.7. See [missing or expired current certificate](https://misiektoja.github.io/cmp-issuer/guide/renewal-and-kur/#missing-or-expired-current-certificate).

### Security and reliability

* **Recorded transaction chains are checked against CMP trust** - A `CMPTransaction` resumed in phase `Issued` or `Confirming` has its chain validated against the current `spec.cmpTrust` anchors before cert-manager receives it or `certConf` is sent. Earlier releases trusted the record, so anyone allowed to write `cmptransactions` status in a namespace could choose the certificate issued there. No role shipped with cmp-issuer grants that access. An issuer whose trust Secret is missing cannot recover an issued chain until the Secret is restored.
* **Strict MAC profiles require 100 iterations on responses** - Under `validationProfile: RFC9483` or `macResponseProtection: Strict` a MAC-protected response with fewer iterations fails with `badMessageCheck`. The interoperable default accepts the count the server chose.

### Bug fixes

* **KUR fails when the current certificate Secret is deleted** - Such a renewal stayed Pending and read the Secret every second. It fails with a message that names the Secret and the ways to recover.
* **KUR no longer renews in a loop when the CA keeps the old validity** - cert-manager renewed again at once when a KUR certificate kept the `notBefore` and `notAfter` of the one it replaced. cmp-issuer rejects such a certificate in `certConf` and fails the `CertificateRequest`. On NCM tick "Overwrite old?" in the `set-validity-period` policy module, see [certificate validity on NCM](https://misiektoja.github.io/cmp-issuer/interoperability/tested-pkis/#certificate-validity).

### Project maintenance

* **Built with Go 1.27.3** - Includes the `crypto/x509` fix GO-2026-6809. Building from source needs Go 1.27.3.
* **CMP library go-pki-cmp v0.8.0** - Encodes the validity that `requestedValidity` sends.
* **Leader election without ConfigMap access** - The leader-election Role grants Leases and Events only.
* **Supply chain checks** - Base images are pinned by digest and the chart repository verifies the chart's build provenance attestation before indexing it.

## [0.3.1] - 11 Oct 2026

This release fixes PasswordBasedMac enrollment with more than 500000 iterations and KUR of certificates without a subject DN. Signature-protected requests carry certificate subjects exactly as the certificates encode them. Kubernetes 1.37 joins the verified versions and the CMP library moves to go-pki-cmp, its new name.

### Bug fixes

* **PasswordBasedMac accepts every allowed iteration count** - An `iterationCount` from 500001 to 1048575 passed validation, but enrollment failed before any request was sent. These counts work for requests and for server responses that use the same count.
* **Certificate subjects are sent as the certificate encodes them** - With signature protection the request sender is the subject of the protection certificate byte for byte and a KUR certificate template repeats the subject of the certificate being updated. These names were encoded again from their parsed form, which can change string types and attribute order, so a server that compares them with the certificate could reject the request.
* **KUR sends a NULL-DN for certificates without a subject** - A certificate named only in its SANs is renewed with an empty subject name in the KUR template, as RFC 9483 requires. The subject was left out before, which servers that enforce the profile reject with `badCertTemplate`.

### Project maintenance

* **Verified on Kubernetes 1.34 to 1.37** - The end-to-end tests run on Kubernetes 1.37 and 1.36 with cert-manager 1.21, 1.35 with cert-manager 1.20 and 1.34 with cert-manager 1.19.
* **CMP library go-pki-cmp v0.4.0** - The library formerly published as go-pkicmp-ng has the module path `github.com/misiektoja/go-pki-cmp`. The recipient and a configured sender name use PrintableString where the value allows it, as X.509 certificates do, instead of always UTF8String.

## [0.3.0] - 9 Oct 2026

This release adds **ML-DSA** support, configured response signer certificates and SHA-384/SHA-512 PasswordBasedMac. It reports refused certificates to CMP servers and fixes Ed25519 protection and verification of responses that omit a configured anchor signer.

### Certificate management

* **Enroll ML-DSA certificates** - Submit ML-DSA-44, ML-DSA-65 or ML-DSA-87 CSRs with compatible cert-manager and CA support. CSR admission depends on the cert-manager build and its feature gates. Automatic renewal and KUR also require cert-manager to manage ML-DSA keys. cmp-issuer rejects ML-DSA certificates with key usages forbidden by RFC 9881. See [build requirements and key usages](https://misiektoja.github.io/cmp-issuer/known-limitations/#ml-dsa).
* **Work with ML-DSA CAs and credentials** - Certificates signed by an ML-DSA CA are confirmed with a SHA-512 `certConf` hash sent as CMPv3, which RFC 9810 requires when `hashAlg` is present. Responses signed with ML-DSA are verified. A signature-protection credential may hold an ML-DSA key in seed-only PKCS #8 form.
* **The issuance log names ML-DSA keys** - `keyType` reports the parameter set, such as `ML-DSA-65`, instead of `Unknown`.

### Security and reliability

* **HTTP/2 security fixes** - Includes fixes for denial-of-service vulnerabilities and invalid-header handling in HTTP/2.
* **Configure response signer certificates separately from trust anchors** - `spec.cmpTrust.signerCertificatesSecretRef` supplies signer certificates and intermediates when the server omits them from `extraCerts`. Every signer still has to chain to `spec.cmpTrust.caSecretRef`. Both validation profiles accept this interoperability allowance and retain the validated signer for polling and confirmation.
* **Select SHA-384 or SHA-512 for PasswordBasedMac** - `owf` and `mac` accept the SHA-256, SHA-384 and SHA-512 family. The MAC digest cannot be longer than the OWF output. SHA-256 and 1024 iterations remain the defaults. The configured suite applies to enrollment, polling and confirmation without fallback.
* **Refused certificates are reported to the CMP server** - When an issued certificate does not certify the requested key, fails chain validation or carries modifications refused by `spec.policy.grantedModifications: Reject`, cmp-issuer sends `certConf` with status `rejection` before failing the `CertificateRequest`. The server no longer waits for a confirmation that never arrives. Under server-granted implicit confirmation no `certConf` is sent.

### Bug fixes

* **Responses signed by a configured trust anchor can omit `extraCerts`** - Both validation profiles accept a response signed by a certificate in `spec.cmpTrust` without the server resending that certificate. The validated signer is retained for polling and confirmation across controller restarts. Trust, signature and transaction checks still apply.
* **Ed25519 signature protection is accepted by CMP servers** - Requests protected with an Ed25519 key carried an Ed25519ph signature labeled as pure Ed25519, so conforming servers rejected them. This broke Ed25519 signature credentials and KUR renewal of Ed25519 certificates. The signature is pure Ed25519.

### Project maintenance

* **Building from source needs Go 1.27.2** - The module requires Go 1.27.2 for ML-DSA support and standard-library security fixes.
* **Contributions need a DCO sign-off** - Every commit must carry a `Signed-off-by` trailer from `git commit -s` that certifies the Developer Certificate of Origin. Pull requests run a DCO check and `make dco-check` runs it locally.

## [0.2.1] - 4 Sep 2026

This release corrects CMP transaction recovery and KUR retry behavior, tightens KUR workload Secret authorization and gives the failure metric label a fixed vocabulary that alerts can match.

### Bug fixes

* **Interrupted confirmations resend `certConf`** - When a server delayed the enrollment and the confirmation that followed was interrupted before the server accepted `certConf`, the resumed transaction polled for an answer to a `certConf` that was never sent and the issued certificate was abandoned. The resumed confirmation sends `certConf`. A transaction that entered this state before the upgrade still fails once and cert-manager enrolls again.
* **KUR renewals retry temporary Kubernetes API failures** - A temporary failure while reading the owning `Certificate` failed the renewal permanently instead of retrying it. Only an absent `Certificate` is final and every other read failure is retried.
* **The `failure` metric label uses a fixed vocabulary** - A CMP response setting several failure bits was counted under the combined bit list, so an alert matching one exact name such as `badMessageCheck` could miss it and a server could mint unbounded metric series. The label carries the most security-relevant bit name and the complete bit list stays in the `CMP enrollment failed` log line. Update dashboards that filter on combined label values.
* **`spec.protocol.certProfile` is documented as reserved** - The field reference presented it as usable while the controller rejects any non-empty value, which made an issuer configured per the documentation permanently NotReady. The documentation and the CRD descriptions mark it reserved and the NCM interoperability workflow no longer offers a variable for it.

### Improvements

* **Unfinished KUR transactions survive metadata-only Secret writes** - The transaction digest identifies both workload Secrets by their UID and the consumed key material instead of resourceVersion, so an annotation or label written by another controller mid-transaction no longer stops the renewal. A key-material change still stops it before more CMP traffic. An unfinished KUR transaction recorded by 0.2.0 fails this check once after the upgrade and cert-manager enrolls again.
* **KUR reads the current key only from a cert-manager output Secret** - Before the current workload key is read, the Secret named by `Certificate.spec.secretName` must carry cert-manager's `cert-manager.io/certificate-name` annotation for the owning `Certificate`, and any controller owner reference on it must name that same `Certificate`. cert-manager writes the annotation whenever it stores an issued certificate and adds the owner reference only with `--enable-certificate-owner-ref`. A Secret replaced by another tool, or shared with a second `Certificate`, fails the renewal with `authorize KUR current certificate`.

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
