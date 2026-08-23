# Contributing

cmp-issuer is a cert-manager external issuer for CMP servers. Bug reports, interoperability results and code contributions are welcome.

## Before contributing

Read [docs/provenance.md](docs/provenance.md) and [docs/security/threat-model.md](docs/security/threat-model.md). [SUPPORT.md](SUPPORT.md) lists where usage questions and bug reports belong. Contribute only code you have the right to license under Apache-2.0, and record any source that materially influenced protocol code in the provenance page.

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

## Code style and local hooks

[.editorconfig](.editorconfig) records the whitespace rules the repository already follows: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes plus two-space indentation for the structured configuration and shell files. Markdown keeps meaningful trailing spaces and `LICENSE` remains verbatim. Most editors apply these settings automatically, while a few need a plugin.

Optional local hooks enforce the same whitespace rules, validate YAML and TOML and reject private keys without installing a Go toolchain:

```bash
pre-commit install
pre-commit run --all-files
```

Install [pre-commit](https://pre-commit.com/) first. CI remains authoritative for golangci-lint, actionlint and the full gitleaks history scan.
