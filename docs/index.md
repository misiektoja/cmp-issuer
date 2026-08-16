# cmp-issuer

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP) servers.

It implements CMPv2 initial enrollment with a PKCS #10 request carried in P10CR and a CP response. CMP message protection is mandatory in both directions. PasswordBasedMac and certificate-signature protection have both completed protected `Certificate` enrollments against NCM 26.7 with Insta Certifier 7.20 and EJBCA Community Edition 9.3.7.

!!! warning "Under active initial development"

    The protocol adapter and the controller foundation are not production ready. The API group `certmanager.misiektoja.github.io` is served at `v1alpha1` and may change.

## Where to start

- [Credential Secret access](operations/secret-access.md) explains the namespace boundary that governs which Secrets the controller may read and the RoleBinding an administrator must create.
- [Threat model](security/threat-model.md) records the trust boundaries, the assets and the mitigations that the design relies on.
- [Provenance and supply chain](provenance.md) describes how releases are built and which artifacts accompany them.

## Design decisions

- [CMP library selection](adr/0001-cmp-library.md) records why the protocol layer is built on a reviewed CMP library instead of a hand written encoder.
- [go-pkicmp review](dependencies/go-pkicmp-review.md) is the dependency review that supports that decision.

## Repository

Installation instructions, the API reference and the interoperability notes live in the [repository README](https://github.com/misiektoja/cmp-issuer#readme).
