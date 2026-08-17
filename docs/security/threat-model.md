# Threat model

## Assets

The controller handles CMP shared secrets, issuer bootstrap private keys, bootstrap certificates, CMP trust anchors, TLS trust anchors, PKCS #10 CSRs and issued certificate chains. For P10CR it must not handle the workload private key.

## Trust boundaries

Kubernetes RBAC protects issuer configuration and credential Secrets. A `CMPIssuer` may read only credential Secrets in its own namespace. A `CMPClusterIssuer` resolves credential Secrets only in the controller-configured cluster resource namespace.

CMP response trust is independent from TLS server trust. CMP PKIProtection is mandatory on every request and response. HTTPS provides confidentiality and transport authentication in addition to message protection. HTTP intentionally provides no transport confidentiality.

cert-manager approval is a network boundary. Unapproved or denied CertificateRequests must cause no CMP request.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Credential exfiltration | Least-privilege Secret RBAC, no secret values in logs or Events and no credentials in command arguments |
| Workload key exfiltration | P10CR never follows private-key Secret annotations and has no need to read workload Secrets |
| Forged CMP response | Validate transaction ID, nonces, response body, response protection and signer trust before accepting a certificate |
| Certificate substitution | Verify the issued leaf public key matches the signed CSR public key and validate the chain against CMP trust |
| P10CR response identifier ambiguity | Accept only the standards value `-1` or the observed legacy value `0`, echo the received value in `certConf` and allow an issuer to pin one value |
| Unverifiable confirmation response | Reuse only the response signer already validated against CMP trust when a server omits `extraCerts` and `senderKID` from `pkiConf`, and still reject invalid protection |
| Unbounded wait for a delayed confirmation | Record the validated chain before `certConf` is sent, then poll for a delayed `pkiConf` from that recorded state under the configured transaction deadline and poll ceiling, rather than holding a reconcile open or discarding an issued certificate |
| Redirect or header state injection | Disable HTTP redirects and derive transaction state only from authenticated CMP DER |
| Resource exhaustion | Bound response size, timeouts, polling, transaction duration and request concurrency |
| Duplicate enrollment after a restart | Record the transaction identifier in a `CMPTransaction` before the first message is sent, resume the recorded transaction on the next reconcile and return the recorded chain when the certificate was already issued |
| Ambiguous timeout on an unanswered enrollment | Pin the transaction identifier before the message reaches the network and retry under it. Both tested servers refuse the repeat under an authenticated error, NCM 26.7 with `transactionIdInUse` and EJBCA CE 9.3.7 with `badRequest`, and neither issues a second certificate. The request fails permanently and cert-manager enrolls again under a new transaction identifier |
| Credential rotation mid-transaction | Not addressed. Credentials are reloaded from the issuer on every reconcile, so a rotated shared secret invalidates the protection of an in-flight transaction and it fails within its configured `maximumDuration` |
| Cross-namespace Secret reference | Secret references contain names and keys only. Namespace selection is fixed by issuer scope |
| Malformed ASN.1 | Fail closed, fuzz parsers and keep the provisional parser behind project-owned interfaces |

## Future CRMF private-key boundary

IR and true KUR require workload private-key access for CRMF proof of possession. A future design must validate the owning Certificate, revision, issuer reference, expected Secret state, owner references, labels, CSR signature and public-key equality before reading only `tls.key`. The annotation `cert-manager.io/private-key-secret-name` is never sufficient authorization by itself.

## Residual risks

go-pkicmp is pre-v1, lightly adopted and has had little independent review. It remains a provisional security-sensitive dependency, so every response it parses is validated again by the project's own checks. CMP interoperability depends on each server's configured profile, algorithms, endpoint and authentication policy.
