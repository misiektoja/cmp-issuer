# Contributing

cmp-issuer is a cert-manager external issuer for CMP servers. Bug reports, interoperability results and code contributions are welcome.

## Before contributing

Read [docs/provenance.md](docs/provenance.md) and [docs/security/threat-model.md](docs/security/threat-model.md). Contribute only code you have the right to license under GPL-3.0-only, and record any source that materially influenced protocol code in the provenance page.

Never commit credentials, private keys, protected CMP messages, full CSRs or non-public PKI documentation. Keep scratch files and local test state out of commits.

## Development checks

Run formatting, static analysis, unit tests and documentation validation before submitting a change. Protocol changes need negative tests and an RFC citation. Interoperability claims need sanitized evidence from the named product and version.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.
