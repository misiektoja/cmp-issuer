# Testing

cmp-issuer validation spans unit tests, envtest, OpenSSL interoperability, Kind e2e and manual verification against real CMP servers.

## Unit and envtest

```bash
make test
```

Coverage includes:

* Protocol adapter encoding and verification
* Signer and controller reconciliation
* Deferred enrollment over real CMP messages with transaction state on a real API server
* Delayed confirmation and nonce echo rules
* Transaction identifier pinning across a retry and recovery of an already issued chain

## OpenSSL CMP interoperability

CI runs delayed transaction, delayed confirmation and pinned transaction flows against the OpenSSL 3.6 CMP mock. The pinned transaction test asserts that the identifier recorded before sending is the identifier OpenSSL saw on the wire, which is what a retry after an interruption reuses. The workflow fails if the test is silently skipped when OpenSSL is available.

Locally set `OPENSSL_BIN` to select a non-default OpenSSL binary. The test skips when OpenSSL is missing.

The mock uses one transaction per TCP connection. A pooling proxy forwards tests without changing CMP bytes.

## Kind e2e suite

```bash
make test-e2e
```

Requires Colima or Docker for Kind. The suite:

* Creates an isolated Kind cluster
* Installs cert-manager and cmp-issuer
* Verifies issuer readiness and Secret naming on failure
* Validates accepted `p10crResponseCertReqId` values
* Confirms denied requests send no CMP traffic and store no certificate
* Confirms connection failures store no partial material
* Confirms crafted private-key annotations do not expose Secrets
* Confirms Secret access requires the documented RoleBinding

Runtime is about one minute after the cluster is ready. **Do not run this suite against a production cluster.**

### Other Kubernetes and cert-manager versions

Two variables select the versions, so one suite covers the whole supported range:

| Variable | Effect |
| --- | --- |
| `KIND_NODE_IMAGE` | Kubernetes version of the Kind cluster, for example `kindest/node:v1.34.0`. Empty uses the default of the pinned Kind release |
| `CERT_MANAGER_VERSION` | cert-manager release the suite installs, for example `v1.19.6` |

```bash
make test-e2e KIND_NODE_IMAGE=kindest/node:v1.34.0 CERT_MANAGER_VERSION=v1.19.6
```

CI runs the suite once per supported combination, so a change that only works on the newest Kubernetes or the newest cert-manager fails before release:

| Kubernetes | cert-manager |
| --- | --- |
| 1.36, the default of the pinned Kind release | v1.21.1 |
| 1.35 | v1.20.3 |
| 1.34 | v1.19.6 |

The two older rows pin a digest, taken from the node images published for the Kind release pinned as `KIND_VERSION` in the `Makefile`, so they have to be updated with it. The newest row pins no image and follows the Kind default.

## Interoperability against real CMP servers

Enrollment against Nokia NCM and EJBCA is verified manually against dedicated CMP servers, because running a certificate authority inside the test cluster costs far more per run than the rest of the suite. Outcomes are summarized in [Tested PKIs](../interoperability/tested-pkis.md).

### Enrolling from a hosted NCM instance in CI

`interop-ncm.yml` performs a complete enrollment against a hosted Nokia NCM instance: it creates a Kind cluster, installs cert-manager and cmp-issuer, stores the endpoint credentials, creates a `CMPIssuer`, enrolls a `Certificate` and inspects the certificate that comes back.

It is the only workflow that reaches a PKI outside the repository, so it never runs on a push or a pull request. Start it from the Actions tab, optionally choosing the Kubernetes and cert-manager versions, and enable the repeat enrollment when the server profile allows the same identity to enroll twice.

### What each run covers

One job runs per protection mechanism and transport, so a fully configured endpoint exercises four independent enrollments:

| | HTTP | HTTPS |
| --- | --- | --- |
| **PasswordBasedMac** | shared secret, plain transport | shared secret, TLS transport |
| **Signature** | request signing certificate, plain transport | request signing certificate, TLS transport |

Each job builds its own Kind cluster, so the four run in parallel and a failure in one does not mask the others. Configure only the transports the server exposes: a missing `NCM_CMP_HTTP_URL` or `NCM_CMP_HTTPS_URL` skips that column rather than failing it. Every job asserts that the endpoint it received actually uses the scheme of its own row, so a secret pasted into the wrong box fails loudly instead of quietly enrolling over HTTP twice.

### Configuration

Configure it under **Settings, Secrets and variables, Actions**. A repository without these values reports what is unconfigured and skips the enrollment rather than failing:

| Secret | Required | Contents |
| --- | --- | --- |
| `NCM_CMP_HTTP_URL` | one URL at least | Plain HTTP CMP endpoint, for example `http://ncm.example:8080/pkix/` |
| `NCM_CMP_HTTPS_URL` | one URL at least | HTTPS CMP endpoint, for example `https://ncm.example/pkix/` |
| `NCM_CMP_RECIPIENT_DN` | yes | Distinguished name of the issuing CA, sent as `spec.protocol.recipient` |
| `NCM_CMP_RESPONSE_TRUST` | yes | PEM anchor that signs the CMP responses and the issued chain |
| `NCM_CMP_PBM_REFERENCE` | for PasswordBasedMac | Reference number identifying the shared secret |
| `NCM_CMP_PBM_SECRET` | for PasswordBasedMac | Shared secret value |
| `NCM_CMP_BOOTSTRAP_CERT` | for Signature | PEM certificate that signs the CMP requests |
| `NCM_CMP_BOOTSTRAP_KEY` | for Signature | PEM private key for that certificate |
| `NCM_CMP_BOOTSTRAP_CHAIN` | no | PEM issuers of that certificate, sent in `extraCerts`, which also sets `chainKey` |
| `NCM_CMP_HTTPS_TRUST` | no | PEM anchor for the HTTPS server certificate, when it is not publicly trusted |

| Variable | Required | Contents |
| --- | --- | --- |
| `NCM_CMP_CERT_PROFILE` | no | Certificate profile sent as `spec.protocol.certProfile` |
| `NCM_CMP_COMMON_NAME` | no | Common name to enroll. Left unset it becomes `cmp-issuer-test-<UTC YYMMDD-HHMMSS>`, so every run enrolls a distinct identity |
| `NCM_CMP_COUNTRY` | no | Country requested in the subject, for example `PL`. Omitted entirely when unset |
| `NCM_CMP_ORGANIZATION` | no | Organization requested in the subject, for example `cmp-issuer`. Omitted entirely when unset |

Leave `NCM_CMP_COMMON_NAME` unset unless you need a fixed name. A server profile that authorizes an identity to enroll only once refuses every run after the first, and a timestamped name sidesteps that without any server-side cleanup between runs.

Requesting a country or an organization is a request, not an instruction. A CA that enforces its own subject answers `grantedWithMods`, which the issuer rejects under `policy.grantedModifications: Reject`, so an enrollment that fails only after these variables are set points at the server profile rather than at the issuer. Clear both to fall back to a bare common name.

`NCM_CMP_RESPONSE_TRUST` and `NCM_CMP_HTTPS_TRUST` are two different anchors and are frequently confused. The first is CMP trust, which verifies the signature protecting the response message and the chain that comes back in it. The second is transport trust, which verifies the TLS server certificate and is used only on the HTTPS rows. A server may present a publicly trusted TLS certificate while issuing from a private CA, in which case only the first is needed. See [HTTP and HTTPS transport](../guide/transport.md).

Every value is written from the environment into a file and read back with `--from-file`, so no credential reaches a command line, and the endpoint URLs and the recipient are secrets rather than variables so a run against a private instance does not print them.

## Lint and supply chain

```bash
make lint
make govulncheck
make gitleaks
make sbom
make scan-image IMG=<image>
```

CI runs these on push and on a weekly schedule.

## Related pages

* [Development](development.md)
* [Release process](release-process.md)
