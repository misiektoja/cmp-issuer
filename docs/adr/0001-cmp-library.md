# ADR 0001: isolate go-pkicmp behind project interfaces

* Status: accepted for initial development

## Context

cmp-issuer needs CMPv2 P10CR, CP, certConf and pkiConf support with PasswordBasedMac and signature protection. Implementing all ASN.1 from scratch would expand the security review substantially. go-pkicmp implements the needed primitives but is pre-v1, lightly adopted, partly incomplete and has had little independent review.

## Decision

Pin go-pkicmp to an exact version. Use it only behind project-owned `ProtocolClient` and `TransactionCodec` interfaces. Do not expose its types through CRDs, public packages or controller contracts.

The pinned version is currently `v0.0.0-20260817124344-a18451f3cf35`, supplied by the fork [github.com/misiektoja/go-pkicmp-ng](https://github.com/misiektoja/go-pkicmp-ng) at branch `cmp-hardening` through a `replace` directive in `go.mod`. The published `v0.0.1` release accepts a signature-protected message from any certificate that chains to a configured trust anchor without checking that it matches the sender the message claims, and it returns an issued certificate without checking that the certificate certifies the key that was requested. Both are in the verification path this project calls directly, so releasing on `v0.0.1` is not acceptable. The fork also corrects PBMAC1 key-length handling, CMP media type parsing, CMP-over-HTTP error handling and response nonce validation on a delayed delivery, and it bounds the poll interval a server can ask for.

The fork keeps the upstream module path, so it is consumed through `replace` rather than through a renamed import. The corrections are proposed upstream. When they are published there, drop the `replace` directive, require the released version and record it here.

Do not use the high-level client's polling loop in reconciliation. The adapter owns HTTP policy, transaction validation, P10CR `certReqId` validation, certificate and CSR public-key matching, confirmation behavior and error classification. It accepts the standards value `-1` and the observed legacy value `0`, echoes the received value in `certConf` and rejects any other value. An issuer may pin one value, after which only that value is accepted.

The adapter also owns cross-message signer state. Once a response signer certificate is validated against the configured CMP trust anchors, the linked confirmation response is verified against that certificate. This keeps verification fail closed on servers that omit `extraCerts` and `senderKID` from `pkiConf`.

## Consequences

The project can replace or patch the dependency without changing its public API. It maintains independent negative tests and interoperability evidence. A dependency defect is reproduced with a minimal failing test and an RFC citation before a patch is proposed.

A `replace` directive applies only when this repository is the main module, which is how the manager image, the installer and the Helm chart are all built. It is ignored when another module imports cmp-issuer as a library and by `go install` at a version, so neither of those routes carries the corrected library. Build from a checkout of this repository until the directive is gone. Dependabot does not propose updates for a replaced module either, so the pinned version is advanced by hand.
