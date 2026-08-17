# cmp-issuer

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP) servers.

It implements CMPv2 initial enrollment with a PKCS #10 request in P10CR and a CP response. CMP message protection is mandatory. HTTP and HTTPS are both supported. PasswordBasedMac and certificate-signature P10CR have completed protected cert-manager `Certificate` enrollments against NCM 26.7 and EJBCA Community Edition 9.3.7.

!!! warning "Under active initial development"

    The protocol adapter and controller foundation are not production ready. The API group `certmanager.misiektoja.github.io` is served at `v1alpha1` and may change.

## Documentation map

| Topic | Page |
| --- | --- |
| Feature support | [Support matrix](support-matrix.md) |
| Components and flow | [Architecture](architecture.md) |
| Install the controller | [Installation](installation.md) |
| Issue certificates | [Enrollment](guide/enrollment.md) |
| Issuer resources | [CMPIssuer](reference/cmpissuer.md), [CMPClusterIssuer](reference/cmpclusterissuer.md) |
| Server-specific notes | [Tested PKIs](interoperability/tested-pkis.md) |
| Persistence gaps | [Known limitations](known-limitations.md) |

## Quick links

* [Credential Secret access](operations/secret-access.md) - namespace boundary for Secret reads
* [Security model](security/security-model.md) and [Threat model](security/threat-model.md)
* [Development](development/development.md) and [Testing](development/testing.md)
* [Provenance and supply chain](provenance.md)

## Design decisions

* [CMP library selection](adr/0001-cmp-library.md)

## Repository

Source, issues and the full README entry point: [github.com/misiektoja/cmp-issuer](https://github.com/misiektoja/cmp-issuer)
