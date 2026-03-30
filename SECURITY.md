# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Until a private GitHub security contact exists, send the maintainer a minimal private report through a previously established private channel. Do not include private keys, shared secrets, full CSRs, protected CMP messages or production endpoint details.

Include the affected revision, impact, reproduction preconditions and a sanitized proof when possible. The maintainer will acknowledge the report and coordinate disclosure after a fix is available.

## Supported versions

The project has no released version yet. Security fixes apply to the current default branch until a release policy is published.

## Security posture

CMP message protection is mandatory for HTTP and HTTPS. HTTPS adds transport confidentiality and server authentication. It does not replace CMP PKIProtection. See [docs/security/threat-model.md](docs/security/threat-model.md).
