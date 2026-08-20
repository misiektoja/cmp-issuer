# ADR 0001: isolate the CMP encoding library behind project interfaces

* Status: accepted

## Context

cmp-issuer needs CMPv2 P10CR, CP, certConf and pkiConf support with PasswordBasedMac and signature protection. Implementing all ASN.1 from scratch would expand the security review substantially. The go-pkicmp family of libraries implements the needed primitives but is pre-v1, lightly adopted, partly incomplete and has had little independent review.

## Decision

Pin the CMP encoding library to an exact version. Use it only behind project-owned `ProtocolClient` and `TransactionCodec` interfaces. Do not expose its types through CRDs, public packages or controller contracts.

The library is [github.com/misiektoja/go-pkicmp-ng](https://github.com/misiektoja/go-pkicmp-ng), pinned at `v0.0.0-20260820223730-7b790fd80fa6`. It is a maintained derivative of [github.com/tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp), whose published `v0.0.1` release accepts a signature-protected message from any certificate that chains to a configured trust anchor without checking that it matches the sender the message claims, and returns an issued certificate without checking that the certificate certifies the key that was requested. Both are in the verification path this project calls directly, so releasing on `v0.0.1` is not acceptable. The derivative also corrects PBMAC1 key-length handling, CMP media type parsing, CMP-over-HTTP error handling and response nonce validation on a delayed delivery, and it bounds the poll interval a server can ask for.

It declares its own module path, so it is required like any other dependency and `go.mod` holds no `replace` directive for it. The corrections were offered upstream in [tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3), which remains open. Moving back to the upstream module, if that changes, is a normal dependency swap recorded here.

Do not use the high-level client's polling loop in reconciliation. The adapter owns HTTP policy, transaction validation, P10CR `certReqId` validation, certificate and CSR public-key matching, confirmation behavior and error classification. It accepts the standards value `-1` and the observed legacy value `0`, echoes the received value in `certConf` and rejects any other value. An issuer may pin one value, after which only that value is accepted.

The adapter also owns cross-message signer state. Once a response signer certificate is validated against the configured CMP trust anchors, the linked confirmation response is verified against that certificate. This keeps verification fail closed on servers that omit `extraCerts` and `senderKID` from `pkiConf`.

## Consequences

The project can replace or patch the dependency without changing its public API. It maintains independent negative tests and interoperability evidence. A dependency defect is reproduced with a minimal failing test and an RFC citation before a patch is proposed.

Because the dependency is an ordinary requirement rather than a `replace`, every consumption route resolves the same corrected library: the manager image, the installer, the Helm chart, `go install` at a version and any module that imports cmp-issuer as a library. Dependabot tracks it like any other module.
