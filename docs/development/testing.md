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

The run writes `cover.out` and reports one figure for `api/` and `internal/` together, set by
`COVER_PACKAGES`. Go otherwise credits coverage only to the package a test binary lives in, which makes
a package holding no test file of its own read as 0% even when every run executes it. Inspect the result
per function with `go tool cover -func=cover.out` or in a browser with `go tool cover -html=cover.out`.
`cmd/` and `test/utils/` are reported as having no test files, which is accurate: the first is manager
wiring and the second is scaffolding for the e2e suite.

`make test` regenerates the CRDs, the RBAC rules and the DeepCopy code before it runs anything, so a
stale generated file is repaired on the spot rather than reported. CI therefore runs `go mod tidy` and
the generation targets in a step of their own and fails when the working tree changed, which is what
turns a forgotten `make manifests generate` into a red run instead of a green one on a tree that no
longer matches the commit. Run `go mod tidy` and `make manifests generate fmt` locally and commit what
they change.

`test/workflows` runs in the same command and checks the GitHub Actions workflow definitions rather than
Go code, so it reports no coverage either. It fails a change that references an action by tag or branch
instead of a commit SHA, that drops the version comment which makes a pinned SHA reviewable, that
interpolates a `${{ }}` expression into a `run:` block instead of passing the value through `env`, or
that adds a workflow with no top-level `permissions` key. These are the conventions every workflow here
already follows, and nothing else enforces them.

`test/repository` checks the repository itself: governance and support files, citation identity and its
released version, EditorConfig settings, tracked-file whitespace, Git line-ending and binary rules plus
the toolchain-free pre-commit hooks. The workflow suite separately requires release source archives,
checksums and signed build provenance. These checks keep metadata changes reviewable through the same
`make test` command as the Go behavior.

## OpenSSL CMP interoperability

CI runs delayed transaction, delayed confirmation, pinned transaction and KUR flows against the OpenSSL CMP mock. The KUR flows have the mock check the oldCertID the request carries, which needs the `-ref_cert` option that OpenSSL added in 3.2, so the workflow installs a current OpenSSL rather than using the runner's 3.0 package. KUR covers new-key and same-key CRMF proof of possession. The pinned transaction test asserts that the identifier recorded before sending is the identifier OpenSSL saw on the wire, which is what a retry after an interruption reuses. The workflow fails if the test is silently skipped when OpenSSL is available.

Locally set `OPENSSL_BIN` to select a non-default OpenSSL binary. The test skips when OpenSSL is missing, and the KUR flows skip on their own when the build predates `-ref_cert` while the other flows still run.

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

CI runs the suite once per supported combination after a change lands on `dev` or `main`. Pull requests
omit this expensive matrix, so a change that only works on the newest Kubernetes or cert-manager is
reported on the development branch before release:

| Kubernetes | cert-manager |
| --- | --- |
| v1.36, the default of the pinned Kind release | v1.21.1 |
| v1.35 | v1.20.3 |
| v1.34 | v1.19.6 |

The two older rows pin a digest, taken from the node images published for the Kind release pinned as `KIND_VERSION` in the `Makefile`, so they have to be updated with it. The newest row pins no image and follows the Kind default.

## Enrollment against a CMP server in the cluster

```bash
make test-e2e-ejbca
```

This runs a second set of specs that enroll real certificates from EJBCA Community Edition running in the same Kind cluster, through cert-manager `Certificate` resources and the full controller path:

| Spec | What it enrolls |
| --- | --- |
| Shared secret over HTTP | `PasswordBasedMac` protected P10CR against a plain endpoint |
| Shared secret over HTTPS | the same request over TLS, with the endpoint certificate verified against a pinned authority |
| Certificate signature over HTTP | `Signature` protected P10CR using a registration certificate |
| KUR with key rotation | P10CR revision one then certificate-authenticated KUR with a new requested key |
| KUR with key reuse | P10CR revision one then certificate-authenticated KUR with the existing key |
| Transaction records | one `CMPTransaction` per enrollment, each reporting `Issued` |

Each issued certificate is checked against the authority that signed it and against the chain stored in its Secret. The CMP response trust anchor and the endpoint TLS trust anchor are two different authorities, so a run also proves the two trust decisions stay separate.

The server image already carries its certification authorities, its CMP aliases and a TLS certificate issued for the Service name the suite uses, so a run costs a container start rather than a certificate authority setup. It is pulled when it has been published and built locally otherwise:

```bash
make ejbca-test-image
```

`EJBCA_VERSION` in the `Makefile` selects the upstream release, and `EJBCA_IMAGE_REVISION` republishes the image after a configuration change. `test/e2e/ejbca/README.md` describes what the image contains and why the aliases are configured the way they are.

CI runs these specs in their own job after a change lands on `dev` or `main` and rebuilds the server
image only when the upstream release it is built from is republished under a new digest. Pull requests
omit the EJBCA job.

## Chart installation

```bash
make helm-lint
make helm-deploy IMG=<image>
```

`make helm-lint` renders the chart and asserts the value combinations that change what is rendered, and
it needs no cluster. `test-chart.yml` installs the chart into a Kind cluster on top of that, and it
installs each mode that changes the arguments the manager is started with or the permissions it is
granted, not only the default values:

| Mode | What an install proves |
| --- | --- |
| Default values | The chart installs and the manager becomes available |
| `rbac.namespaced=true` | The namespaced Role and its bindings are the ones the manager is granted |
| `metrics.secure=false` | The plain HTTP metrics endpoint starts instead of failing at flag parsing |
| `metrics.tls.certManager.enabled=true` | The manager mounts the certificate cert-manager issues for the metrics endpoint |

Every install waits for the Deployment to become available, which is how a mode that renders correctly
but leaves the manager unable to start is caught. The release is uninstalled between modes, because a
RoleBinding `roleRef` is immutable and upgrading an existing release into namespaced RBAC fails for a
reason that says nothing about the chart. The workflow runs on a pull request only when the chart or a
build input changes.

## Interoperability against real CMP servers

Enrollment against Nokia NCM is verified against a dedicated CMP server, because that product is not distributable as a test image. Outcomes are summarized in [Tested PKIs](../interoperability/tested-pkis.md).

### Enrolling from a hosted NCM instance in CI

`interop-ncm.yml` performs a complete enrollment against a hosted Nokia NCM instance: it creates a Kind cluster, installs cert-manager and cmp-issuer, stores the endpoint credentials, creates a `CMPIssuer`, enrolls a `Certificate` and inspects the certificate that comes back.

It is the only workflow that reaches a PKI outside the repository. It runs automatically for trusted
pushes to `dev` and `main` and once a week, but never for pull requests. Start it from the Actions tab to
choose different Kubernetes or cert-manager versions and to enable repeat enrollment when the server
profile allows the same identity to enroll twice. Automatic runs use the default Kind node and
cert-manager v1.20.3.

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
make go-patch-check
make scan-image IMG=<image>
```

Pull requests run lint, govulncheck and the credential scan. Pushes to `dev` and `main` additionally
generate the SBOM and build and scan the container image. The weekly schedule repeats the full set so a
newly disclosed vulnerability is found without a source change.

`.gitleaks.toml` extends the default rule set. It allowlists `local/`, `bin/`, `dist/` and `site/` by path, and it allowlists Go identifier names so that the generic credential rule does not report a camelCase or snake_case parameter such as `enableRFC9483` that happens to sit next to a word like `key`. That allowlist is scoped to Go files and to the identifier shape alone, so a high-entropy literal in the same file is still reported. Add a new entry only for a confirmed false positive, and keep it narrow enough that a real credential in the same position would still fail the scan.

`make go-patch-check` reports whether `go.mod` still names the newest Go patch in the release series it targets and `make go-patch-update` moves it there. Standard library security fixes ship in patch releases, so a module left on an older patch has govulncheck report them even though no dependency changed. `go-patch.yml` runs the same check weekly and opens the bump as a pull request against `dev`. The release series is never advanced automatically, because a minor bump is a compatibility decision rather than a security one.

golangci-lint is built with the logcheck module plugin, which `.custom-gcl.yml` pins to an exact
version so that a fresh run analyses the code with the same reviewed plugin as the last one. Editing
that file rebuilds the custom binary on the next `make lint`.

`make lint` runs golangci-lint over the Go code and actionlint over `.github/workflows`. actionlint
delegates `run:` blocks to shellcheck when it is on PATH, which it is on the GitHub-hosted runners, so
install shellcheck locally to see the same findings CI does. `codeql.yml` additionally runs CodeQL
static analysis over the Go code on pushes to `dev` and `main` and weekly. It skips without starting a
runner while the repository is private, then reports under Security, Code scanning after the repository
becomes public.

## Related pages

* [Development](development.md)
* [Release process](release-process.md)
