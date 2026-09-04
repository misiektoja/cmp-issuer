# ADR 0001: isolate the CMP encoding library behind project interfaces

* Status: accepted, context revised after the library moved under this project's maintenance

## Context

cmp-issuer needs CMPv2 P10CR, CP, certConf and pkiConf support with PasswordBasedMac and signature
protection. Implementing all ASN.1 from scratch would expand the security review substantially, so the
project depends on a library for the encoding and protection layer.

The library it started from, `github.com/tsaarni/go-pkicmp`, implemented the needed primitives but was
pre-v1, lightly adopted, partly incomplete and had seen little review outside its own author. That is what
made isolation behind project-owned interfaces the condition of using it at all: the project had to be
able to validate every response independently and to replace the dependency without changing its own
API.

Reviewing it against the RFCs produced corrections the published release did not have, including two
in the verification path this project calls directly. They were offered upstream and remain unmerged,
so the dependency is now `github.com/misiektoja/go-pkicmp-ng`, a derivative maintained by this
project's author. The library is still pre-v1 and still lightly adopted. What changed is who can fix
it and who reads it: the correction path is no longer blocked, and the second reader that an outside
dependency provided is gone. The Consequences section records what follows from that.

## Decision

Pin the CMP encoding library to an exact version. Use it only behind project-owned `ProtocolClient` and `TransactionCodec` interfaces. Do not expose its types through CRDs, public packages or controller contracts.

The library is [github.com/misiektoja/go-pkicmp-ng](https://github.com/misiektoja/go-pkicmp-ng), pinned at `v0.0.4`. It is a maintained derivative of [github.com/tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp), whose published `v0.0.1` release accepts a signature-protected message from any certificate that chains to a configured trust anchor without checking that it matches the sender the message claims, and returns an issued certificate without checking that the certificate certifies the key that was requested. Both are in the verification path this project calls directly, so releasing on `v0.0.1` is not acceptable. The derivative also corrects PBMAC1 key-length handling, CMP media type parsing, CMP-over-HTTP error handling and response nonce validation on a delayed delivery, bounds the poll interval a server can ask for and encodes CRMF `oldCertID` for unambiguous key updates.

It declares its own module path, so it is required like any other dependency and `go.mod` holds no `replace` directive for it. The pin is a tagged release rather than an untagged commit, so `go.mod` names a published immutable version that Dependabot and a bill of materials can both resolve. The corrections were offered upstream in [tsaarni/go-pkicmp#3](https://github.com/tsaarni/go-pkicmp/pull/3), which remains open. Its branch lives in [misiektoja/go-pkicmp-fork](https://github.com/misiektoja/go-pkicmp-fork), a fork kept so that pull request stays intact. Moving back to the upstream module, if that changes, is a normal dependency swap recorded here.

Do not use the high-level client's polling loop in reconciliation. The adapter owns HTTP policy, transaction validation, P10CR `certReqId` validation, certificate and CSR public-key matching, confirmation behavior and error classification. It accepts the standards value `-1` and the observed legacy value `0`, echoes the received value in `certConf` and rejects any other value. An issuer may pin one value, after which only that value is accepted.

The adapter also owns cross-message signer state. Once a response signer certificate is validated against the configured CMP trust anchors, the linked confirmation response is verified against that certificate. This keeps verification fail closed on servers that omit `extraCerts` and `senderKID` from `pkiConf`.

## Consequences

The project can replace or patch the dependency without changing its public API. It maintains independent negative tests and interoperability evidence. A dependency defect is reproduced with a minimal failing test and an RFC citation before a patch is proposed.

Isolating the library was originally a hedge against a third-party dependency that could not be corrected on this project's schedule. That risk is gone now that the library is maintained here, and a different one takes its place: the library and cmp-issuer share an author, so a mistaken reading of a specification can be made on both sides of the interface at once. The independent re-validation of every response is what stands in for the second reader an outside dependency would otherwise have provided, which makes it more load bearing than before rather than less. It stays, and so does the rule that a defect is reproduced against the RFC rather than against the library's own behavior.

Because the dependency is an ordinary requirement rather than a `replace`, every consumption route resolves the same corrected library: the manager image, the installer, the Helm chart, `go install` at a version and any module that imports cmp-issuer as a library. Dependabot tracks it like any other module.
