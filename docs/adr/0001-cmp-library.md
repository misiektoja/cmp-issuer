# ADR 0001: isolate go-pkicmp behind project interfaces

* Status: accepted for initial development

## Context

cmp-issuer needs CMPv2 P10CR, CP, certConf and pkiConf support with PasswordBasedMac and signature protection. Implementing all ASN.1 from scratch would expand the security review substantially. go-pkicmp implements the needed primitives but is pre-v1, lightly adopted, partly incomplete and has had little independent review.

## Decision

Pin go-pkicmp to commit `66dd5e04fc1fe56f3724eba145787f0394a91c69`. Use it only behind project-owned `ProtocolClient` and `TransactionCodec` interfaces. Do not expose its types through CRDs, public packages or controller contracts.

Do not use the high-level client's polling loop in reconciliation. The adapter owns HTTP policy, transaction validation, P10CR `certReqId` validation, certificate and CSR public-key matching, confirmation behavior and error classification. It accepts the standards value `-1` and the observed legacy value `0`, echoes the received value in `certConf` and rejects any other value. An issuer may pin one value, after which only that value is accepted.

The adapter also owns cross-message signer state. Once a response signer certificate is validated against the configured CMP trust anchors, the linked confirmation response is verified against that certificate. This keeps verification fail closed on servers that omit `extraCerts` and `senderKID` from `pkiConf`.

## Consequences

The project can replace or patch the dependency without changing its public API. It must maintain independent negative tests and interoperability evidence. A dependency defect needs a minimal failing test and RFC basis before a local patch is proposed. A public fork requires separate authorization.
