# cmp-issuer

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP) servers.

The first implementation target is CMPv2 initial enrollment with a PKCS #10 request carried in P10CR and a CP response. CMP message protection is mandatory. HTTP and HTTPS are both supported transports. HTTP does not provide transport confidentiality.

This repository is under active initial development. The protocol adapter and controller foundation are not production ready. No successful PKI interoperability result is claimed.

## API foundation

The API group is `certmanager.misiektoja.github.io` with `CMPIssuer` and `CMPClusterIssuer` kinds at `v1alpha1`. A namespaced issuer reads credential Secrets only from its namespace. A cluster issuer reads them only from the controller's configured cluster resource namespace.

PasswordBasedMac with SHA-256 and HMAC-SHA-256 plus certificate-based signature protection are implemented behind a project-owned protocol interface. The current milestone supports synchronous CMPv2 P10CR and CP with explicit or server-granted implicit confirmation. Pending transactions fail closed until durable transaction persistence is implemented.

## Security boundaries

For P10CR the controller forwards the signed PKCS #10 CSR supplied by cert-manager. It does not read the workload private key or cert-manager's staging private-key Secret. TLS trust and CMP response-protection trust are configured separately.

See [the threat model](docs/security/threat-model.md) and [provenance record](docs/provenance.md) before evaluating the project.

Secret access is intentionally not cluster-wide. The base installation grants access only in `cmp-issuer-system` for `CMPClusterIssuer` credentials. Each namespace that uses `CMPIssuer` requires an administrator-created RoleBinding as described in [credential Secret access](docs/operations/secret-access.md).

## Current interoperability blockers

Direct testing against the first NCM lab target found two blockers. PasswordBasedMac P10CR reaches a protected CP response but the response uses `certReqId 0` instead of the RFC 9483 P10CR value `-1`. Certificate-protected P10CR receives a CMP response whose signature cannot be validated by the reviewed dependency or the adapter's independently trust-anchored fallback. Both paths fail closed and no end-to-end cert-manager claim is made.

## License

Original cmp-issuer code is licensed under GPL-3.0-only. Dependencies retain their own licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
