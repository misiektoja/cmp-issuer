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

`interop-ncm.yml` performs a complete enrollment against a hosted Nokia NCM instance: it creates a Kind cluster, installs cert-manager and cmp-issuer, stores the endpoint credentials, creates a `CMPIssuer`, enrolls a `Certificate` and inspects the certificate that comes back. It runs both protection mechanisms as separate jobs.

It is the only workflow that reaches a PKI outside the repository, so it never runs on a push or a pull request. Start it from the Actions tab, optionally choosing the Kubernetes and cert-manager versions, and enable the repeat enrollment when the server profile allows the same identity to enroll twice.

Configure it under **Settings, Secrets and variables, Actions**. A repository without these values reports which mechanisms are unconfigured and skips the enrollment rather than failing:

| Secret | Required | Contents |
| --- | --- | --- |
| `NCM_CMP_URL` | yes | CMP endpoint URL |
| `NCM_CMP_RECIPIENT` | yes | Recipient distinguished name of the issuing CA |
| `NCM_CMP_TRUST` | yes | PEM anchor that signs the CMP responses |
| `NCM_CMP_PBM_REFERENCE` | for PasswordBasedMac | Reference value |
| `NCM_CMP_PBM_SECRET` | for PasswordBasedMac | Secret value |
| `NCM_CMP_SIGNER_CERT` | for Signature | PEM certificate that protects the request |
| `NCM_CMP_SIGNER_KEY` | for Signature | PEM private key for that certificate |
| `NCM_CMP_SIGNER_CHAIN` | no | PEM chain sent in `extraCerts`, which also sets `chainKey` |
| `NCM_CMP_TLS_TRUST` | no | PEM anchor for the HTTPS server certificate |

| Variable | Required | Contents |
| --- | --- | --- |
| `NCM_CMP_CERT_PROFILE` | no | Certificate profile sent as `spec.protocol.certProfile` |
| `NCM_CMP_COMMON_NAME` | no | Common name to enroll, default `cmp-issuer-interop.example` |

Every value is written from the environment into a file and read back with `--from-file`, so no credential reaches a command line, and the endpoint and recipient are secrets rather than variables so a run against a private instance does not print them.

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
