# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Report it privately through [GitHub security advisories](https://github.com/misiektoja/cmp-issuer/security/advisories/new), which keeps the report visible only to the maintainer until an advisory is published. If you cannot use that, email <misiektoja-github@rm-rf.ninja>.

Do not include private keys, shared secrets, full CSRs, protected CMP messages or production endpoint details in a report. Include the affected revision, the impact, the preconditions to reproduce it and a sanitized proof when you have one.

The maintainer will acknowledge the report and coordinate disclosure once a fix is available.

## Supported versions

Security fixes are made on the default branch and shipped in the next release: the [GitHub releases](https://github.com/misiektoja/cmp-issuer/releases), the Helm chart repository at `https://misiektoja.github.io/cmp-issuer/charts` and the manager image on the GitHub Container Registry. Only the latest released version is supported. Earlier versions receive no backports.


## Security posture

CMP message protection is mandatory for HTTP and HTTPS. HTTPS adds transport confidentiality and server authentication. It does not replace CMP PKIProtection. See [the threat model](https://misiektoja.github.io/cmp-issuer/security/threat-model/).
