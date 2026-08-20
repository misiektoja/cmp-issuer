# Contributing

cmp-issuer is a cert-manager external issuer for CMP servers. Bug reports, interoperability results and code contributions are welcome.

## Before contributing

Read [docs/provenance.md](docs/provenance.md) and [docs/security/threat-model.md](docs/security/threat-model.md). Contribute only code you have the right to license under Apache-2.0, and record any source that materially influenced protocol code in the provenance page.

Never commit credentials, private keys, protected CMP messages, full CSRs or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the lightweight checks, while the full Kubernetes,
EJBCA and hosted NCM coverage runs automatically after an accepted change lands on `dev`.

## Development checks

Run these before submitting a change:

```bash
make lint
make test
make docs-build
```

`make test` also runs `go fmt` and `go vet`. Run `make test-e2e` when the controller or the end-to-end specs change, `make test-e2e-ejbca` when the change touches enrollment, since that one issues real certificates from a CMP server started in the test cluster, and `make helm-lint` when the chart changes.

Protocol changes need negative tests and an RFC citation. Interoperability claims need sanitized evidence naming the product and version.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.
