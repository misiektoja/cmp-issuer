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
| P10CR response identifier ambiguity | Require one configured `certReqId`, default to the standards value `-1` and expose legacy `0` only as an explicit per-issuer choice |
| Redirect or header state injection | Disable HTTP redirects and derive transaction state only from authenticated CMP DER |
| Resource exhaustion | Bound response size, timeouts, polling, transaction duration and request concurrency |
| Replay after an ambiguous timeout | Durable transaction work will persist exact protected outbound DER before transmission |
| Credential rotation mid-transaction | Durable transaction work will bind issuer and Secret resource versions to each transaction |
| Cross-namespace Secret reference | Secret references contain names and keys only. Namespace selection is fixed by issuer scope |
| Malformed ASN.1 | Fail closed, fuzz parsers and keep the provisional parser behind project-owned interfaces |

## Future CRMF private-key boundary

IR and true KUR require workload private-key access for CRMF proof of possession. A future design must validate the owning Certificate, revision, issuer reference, expected Secret state, owner references, labels, CSR signature and public-key equality before reading only `tls.key`. The annotation `cert-manager.io/private-key-secret-name` is never sufficient authorization by itself.

## Residual risks

go-pkicmp is pre-v1, lightly adopted and has had little independent review. It remains a provisional security-sensitive dependency. CMP interoperability depends on each server's configured profile, algorithms, endpoint and authentication policy.
