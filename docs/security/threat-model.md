# Threat model

## Assets

The controller handles CMP shared secrets, issuer bootstrap private keys, bootstrap certificates, CMP trust anchors, TLS trust anchors, PKCS #10 CSRs and issued certificate chains. P10CR must not handle workload private keys. KUR temporarily handles the current and requested workload private keys after authenticating their cert-manager ownership chain.

## Trust boundaries

Kubernetes RBAC protects issuer configuration and credential Secrets. A `CMPIssuer` may read only credential Secrets in its own namespace. A `CMPClusterIssuer` resolves credential Secrets only in the controller-configured cluster resource namespace.

CMP response trust is independent from TLS server trust. CMP PKIProtection is mandatory on every request and response. HTTPS provides confidentiality and transport authentication in addition to message protection. HTTP intentionally provides no transport confidentiality.

cert-manager approval is a network boundary. Unapproved or denied CertificateRequests must cause no CMP request.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Credential exfiltration | Least-privilege Secret RBAC, no secret values in logs or Events and no credentials in command arguments |
| Workload key exfiltration | P10CR never follows private-key Secret annotations. KUR verifies the controlling Certificate name and UID, revision, issuer reference, the current Secret and its cert-manager provenance, next-key status, staged Secret owner and label plus CSR key equality before reading either key |
| Annotation-selected arbitrary Secret read | Treat `cert-manager.io/private-key-secret-name` only as one value in an authenticated cert-manager ownership chain and reject before a Secret read when that chain is absent or inconsistent |
| KUR authorized with the wrong certificate | Require the current certificate and key to match, require current validity and digital-signature Key Usage when present then preserve the subject and SAN set in the CRMF template |
| KUR requested-key substitution | Match the staged private key to the signed CSR and use that key for CRMF proof of possession |
| Ambiguous KUR send followed by another operation | Persist `KUR` before the first send and never fall back to P10CR. Retry only the same operation under the recorded transaction identifier |
| Forged CMP response | Require the configured protection mechanism then validate transaction ID, nonces, response body and signer trust before accepting a certificate |
| Certificate substitution | Verify the issued leaf public key matches the signed CSR public key and validate the chain against CMP trust |
| Impersonation by another authority under the same anchor | Require every response to name the authority configured as `spec.protocol.recipient`. Trust anchors establish that a responder is trusted, not which responder answered, so under a shared root any subordinate CA would otherwise satisfy protection verification. The comparison ignores attribute order. A response without a sender name is rejected because it cannot be bound to the configured authority |
| P10CR response identifier ambiguity | Accept only the standards value `-1` or the observed legacy value `0`, echo the received value in `certConf` and allow an issuer to pin one value |
| Unverifiable confirmation response | Reuse only the response signer already validated against CMP trust when a server omits `extraCerts` and `senderKID` from `pkiConf`, and still reject invalid protection |
| Unbounded wait for a delayed confirmation | Record the validated chain before `certConf` is sent, then poll for a delayed `pkiConf` from that recorded state under the configured transaction deadline and poll ceiling, rather than holding a reconcile open or discarding an issued certificate |
| Redirect or header state injection | Disable HTTP redirects and derive transaction state only from authenticated CMP DER |
| Resource exhaustion | Bound response size, timeouts, polling, transaction duration and request concurrency |
| Duplicate enrollment after a restart | Record the transaction identifier plus issuer and credential configuration identity in a `CMPTransaction` before the first message is sent, resume only that bound transaction on the next reconcile and return the recorded chain when the certificate was already issued |
| Removal of transaction state belonging to another request | Condition every delete of a `CMPTransaction` on the UID that was read, so a record deleted and recreated under the same name keeps the state of the request that created it |
| Ambiguous timeout on an unanswered enrollment | Pin the transaction identifier before the message reaches the network and retry under it. Both tested servers refuse the repeat under an authenticated error, Nokia NCM 26.7 with `transactionIdInUse` and EJBCA CE 9.3.7 with `badRequest`, and neither issues a second certificate. The request fails permanently and cert-manager enrolls again under a new transaction identifier |
| Credential or KUR workload key rotation mid-transaction | Record each credential Secret UID and resourceVersion plus each KUR workload Secret UID and key-material digest before the first message, then stop an unfinished transaction before more CMP traffic when any identity changes. The workload digest covers the consumed keys only, so a metadata-only write by another controller does not stop the transaction |
| Cross-namespace Secret reference | Secret references contain names and keys only. Namespace selection is fixed by issuer scope |
| Malformed ASN.1 | Fail closed, fuzz parsers and keep the parser behind project-owned interfaces |

## KUR private-key boundary

The existing certificate key protects KUR while the requested key proves possession. With `rotationPolicy: Always` these are distinct Secrets. With `Never` they can contain the same private key. The annotation `cert-manager.io/private-key-secret-name` is never sufficient authorization by itself.

The manager has cluster-wide `get` permission for cert-manager Certificates because it must resolve the controlling owner. It has no list, watch or mutation permission for Certificates. Secret access remains bound per namespace through RoleBindings. A cluster issuer needs that binding in each workload namespace that selects KUR.

IR also requires CRMF proof of possession but remains planned. It must reuse or strengthen this boundary rather than adding an annotation-only path.

## Residual risks

The CMP encoding layer is pre-v1 and lightly adopted, and it is maintained by this project's author rather than by an independent party. Every response it parses is therefore validated again by cmp-issuer's own checks, which is what stands in for the second reader a third-party dependency would otherwise have. It corrects sender binding on a signature-protected message and checks that an issued certificate certifies the requested key, neither of which the library it derives from does. See [ADR 0001](../adr/0001-cmp-library.md). CMP interoperability depends on each server's configured profile, algorithms, endpoint and authentication policy.
