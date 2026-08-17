# cmp-issuer

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP) servers.

The first implementation target is CMPv2 initial enrollment with a PKCS #10 request carried in P10CR and a CP response. CMP message protection is mandatory. HTTP and HTTPS are both supported transports. HTTP does not provide transport confidentiality.

This repository is under active initial development. PasswordBasedMac and certificate-signature P10CR have both completed protected cert-manager `Certificate` enrollments against two independent CMP servers: NCM 26.7 with Insta Certifier 7.20 and EJBCA Community Edition 9.3.7.

## Documentation

Full documentation is published from the `docs/` site. Build it locally with `make docs-build`.

| Topic | Link |
| --- | --- |
| Support matrix | [docs/support-matrix.md](docs/support-matrix.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Installation | [docs/installation.md](docs/installation.md) |
| Enrollment guide | [docs/guide/enrollment.md](docs/guide/enrollment.md) |
| CMPIssuer reference | [docs/reference/cmpissuer.md](docs/reference/cmpissuer.md) |
| Tested PKIs | [docs/interoperability/tested-pkis.md](docs/interoperability/tested-pkis.md) |
| Known limitations | [docs/known-limitations.md](docs/known-limitations.md) |
| Threat model | [docs/security/threat-model.md](docs/security/threat-model.md) |

## API foundation

The API group is `certmanager.misiektoja.github.io` with `CMPIssuer` and `CMPClusterIssuer` kinds at `v1alpha1`. A namespaced issuer reads credential Secrets only from its namespace. A cluster issuer reads them only from the controller's configured cluster resource namespace.

PasswordBasedMac with SHA-256 and HMAC-SHA-256 plus certificate-based signature protection are implemented. The current milestone supports CMPv2 P10CR and CP with explicit or server-granted implicit confirmation and asynchronous transactions when the server answers `waiting`.

`initialEnrollment` accepts only `P10CR`. IR needs CRMF proof of possession over the workload private key, which the issuer deliberately never reads.

## Asynchronous transactions

Certificate authorities that queue requests answer enrollment with `waiting` instead of a certificate. The issuer polls with `pollReq` until the CA returns the certificate.

Transaction state is recorded in a `CMPTransaction` resource owned by the `CertificateRequest`, so a controller restart resumes the existing transaction rather than enrolling a second time. Configure bounds in `spec.transaction`.

See [Transaction recovery](docs/guide/transaction-recovery.md) and [Known limitations](docs/known-limitations.md) for persistence scope and gaps.

## Security boundaries

For P10CR the controller forwards the signed PKCS #10 CSR supplied by cert-manager. It does not read the workload private key. TLS trust and CMP response-protection trust are configured separately.

Secret access is intentionally not cluster-wide. Add the RoleBinding from [credential Secret access](docs/operations/secret-access.md) for every namespace that uses a `CMPIssuer`.

## P10CR response compatibility

By default the issuer accepts `certReqId` `-1` or `0` in P10CR CP responses, echoes the received value in `certConf` and rejects any other value. Pin one value with `spec.protocol.p10crResponseCertReqId` when a server's behavior is known. Details are in the [CMPIssuer reference](docs/reference/cmpissuer.md) and [Tested PKIs](docs/interoperability/tested-pkis.md).

## Automated verification

| Command | Purpose |
| --- | --- |
| `make test` | Unit, protocol, controller and envtest suites including deferred CMP transactions |
| `make test-e2e` | Kind-based controller tests without a CMP server |
| `make docs-build` | Strict documentation build |
| `make helm-lint` | Helm chart validation |
| `make govulncheck` | Known reachable vulnerabilities |
| `make gitleaks` | Credential scan of tree and history |

OpenSSL CMP mock interoperability runs in CI on every push. Real CMP server testing is summarized in [Tested PKIs](docs/interoperability/tested-pkis.md).

## Installation

```bash
make build-installer IMG=<registry>/cmp-issuer:<tag>
kubectl apply -f dist/install.yaml
```

Or install the Helm chart from `charts/chart`. See [Installation](docs/installation.md).

## License

Original cmp-issuer code is licensed under GPL-3.0-only. Dependencies retain their own licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
