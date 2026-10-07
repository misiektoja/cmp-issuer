# ADR 0001: isolate the CMP encoding library behind the protocol client

* Status: accepted

## Context

cmp-issuer needs CMP encoding and message protection for P10CR enrollment, KUR, polling and certificate confirmation. A library supplies the ASN.1 and cryptographic message operations. The controller must retain control over transaction state and response validation.

The original dependency was `github.com/tsaarni/go-pkicmp`. Corrections to sender binding, requested-key matching and other protocol behavior were proposed in [tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3). cmp-issuer uses the maintained derivative [go-pkicmp-ng](https://github.com/misiektoja/go-pkicmp-ng).

## Decision

Pin `github.com/misiektoja/go-pkicmp-ng` at `v0.3.1`. Keep its types inside `internal/protocol`. The controller uses the `protocol.Client` interface and project-owned request and result types.

The adapter owns HTTP policy, transaction validation, response signer state, certificate validation, confirmation and error classification. The controller persists waiting and confirmation state between calls. The adapter does not use the library's polling loop.

P10CR responses may use the standard `certReqId` of `-1` or the legacy value `0`. An issuer can require one value. The adapter echoes the accepted identifier in `certConf` and rejects other values.

A validated response signer is retained for polling and confirmation when a later response omits `extraCerts` or `senderKID`. Signature, sender, trust and transaction checks still apply.

## Consequences

The dependency can be replaced without changing CRDs or controller contracts. It is an ordinary tagged module requirement with no `replace` directive.

The library and adapter share a maintainer, so their checks can share the same specification mistake. Negative tests must cite the relevant RFC behavior. OpenSSL tests and NCM and EJBCA interoperability tests provide independent evidence. A suspected library defect needs a failing reproducer and an RFC citation.
