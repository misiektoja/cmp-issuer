# cmp-issuer

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/cmp-issuer?style=flat-square&color=blue)](https://github.com/misiektoja/cmp-issuer/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/misiektoja/cmp-issuer/blob/main/LICENSE)
[![Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml)
[![E2E Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml)
[![Supply chain](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/misiektoja/cmp-issuer/badge)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/cmp-issuer)

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP)
servers.

Point a cert-manager `Certificate` at a `CMPIssuer` and the certificate is enrolled over CMPv2 with the resulting certificate written to the usual TLS Secret.

CMP message protection is mandatory. HTTP and HTTPS are both supported.

Currently, enrollment and renewal are supported using PasswordBasedMac (PSK) or certificate-based signature protection for CMP P10CR requests.

## Start here

**[Getting started](getting-started.md)** walks from an empty cluster to an issued certificate in five
steps. If you are new to cmp-issuer, read that page first and come back here for detail.

## Where to go next

| I want to | Page |
| --- | --- |
| Install a different way, or understand the CRD lifecycle | [Installation](installation.md) |
| Know what is supported today | [Support matrix](support-matrix.md) |
| Understand the request lifecycle | [Enrollment](guide/enrollment.md) |
| Choose a protection mode | [Message protection](guide/message-protection.md) |
| Configure which CA responses are trusted | [CMP response trust](guide/cmp-response-trust.md) |
| Move off plain HTTP | [HTTP and HTTPS transport](guide/transport.md) |
| Look up every field | [CMPIssuer](reference/cmpissuer.md), [CMPClusterIssuer](reference/cmpclusterissuer.md) |
| Find notes for my CMP server | [Tested PKIs](interoperability/tested-pkis.md) |
| Watch enrollments on a dashboard | [Metrics](operations/metrics.md) |
| Fix something that is stuck | [Troubleshooting](operations/troubleshooting.md) |
| Understand what is not done yet | [Known limitations](known-limitations.md) |

## Design and operations

* [Architecture](architecture.md) - components and message flow
* [Credential Secret access](operations/secret-access.md) - the namespace boundary for Secret reads
* [Transaction recovery](guide/transaction-recovery.md) - what survives a controller restart
* [Security model](security/security-model.md) and [Threat model](security/threat-model.md)
* [Provenance and supply chain](provenance.md)
* [CMP library selection](adr/0001-cmp-library.md) and [issuer reconciliation library](adr/0002-issuer-lib.md)

## Contributing

* [Development](development/development.md) and [Testing](development/testing.md)
* Source and issues: [github.com/misiektoja/cmp-issuer](https://github.com/misiektoja/cmp-issuer)
