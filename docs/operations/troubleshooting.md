# Troubleshooting

Common failure modes and where to look. Never paste credential values, private keys or protected CMP DER into tickets or Events.

## Issuer not Ready

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Ready=False, message names a Secret | Credential or trust Secret missing or unreadable | Create the Secret; for `CMPIssuer` add the RoleBinding from [Credential Secret access](secret-access.md) |
| Ready=False after install | Controller not running | `kubectl -n cmp-issuer-system get pods` |

## CertificateRequest stuck or failed

```bash
kubectl describe certificaterequest <name> -n <namespace>
kubectl get cmptransactions -n <namespace>
kubectl logs -n cmp-issuer-system deploy/cmp-issuer-controller-manager -c manager
```

| Condition message pattern | Likely cause |
| --- | --- |
| P10CR CP certReqId | Server returned an unexpected identifier; adjust `p10crResponseCertReqId` or use default |
| Response protection / trust | Wrong CMP trust anchors or unexpected signer |
| Response sender does not name the configured recipient | The server answers under a different name than `spec.protocol.recipient`. Set the recipient to the name the server puts in its responses. Attribute order does not matter, so only a genuine difference in attributes or values causes this |
| Transaction deadline / maximum polls | Server queue too slow; increase `spec.transaction` limits |
| Connection refused / timeout | Wrong URL, network policy or server down |
| HTTP redirect rejected | Endpoint redirects; use the final CMP URL |
| Recorded CMP transaction enrolls a different request | The `CMPTransaction` was edited or corrupted; delete it so the request enrolls again |
| `transactionIdInUse`, or `badRequest` naming a `GENERATED` end entity | The controller resent an enrollment the server had already accepted, so its response was lost. No second certificate was issued. cert-manager enrolls again under a new transaction identifier |

The transaction `Phase` column tells you where a request stopped. `Enrolling` means the enrollment is unanswered and will be resent unchanged. `Polling` means the server asked for `pollReq`. `Confirming` means the certificate is issued and recorded, and only the confirmation is outstanding. `Issued` means the certificate is confirmed and recorded, and no further CMP traffic will be sent.

## EJBCA client mode

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Refused after first success | End entity in GENERATED state | Reset end entity status to NEW before repeat enrollment |
| Subject mismatch | Signature mode enrolls bootstrap DN only | Match Certificate SAN/CN to registered end entity or use PBM with correct profile |
| Wrong protection | Alias authentication modules | Confirm alias uses HMAC for PBM and EndEntityCertificate for signature |

## NCM

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Header protection failed with vendor client | Missing end-entity cert in P10CR extraCerts | Use cmp-issuer layout or fix client |
| pkiConf verification failed before fix | Signer not retained | Upgrade to a build with confirmation signer retention |
| Pinning certReqId -1 | NCM returns 0 | Omit pin or set `p10crResponseCertReqId: 0` |

## Denied or unapproved requests

cmp-issuer sends **no** CMP message for unapproved or denied `CertificateRequest` resources. Verify cert-manager approval policies and `CertificateRequest` conditions.

Note: issuer-lib treats a freshly denied request as neither approved nor denied when `Ready=False` with reason `Denied` instead of a `Denied` condition type. Denied requests still produce no CMP traffic in practice.

## Invalid protection tests

Wrong PSK or invalid response signer fail closed: no certificate accepted and no TLS Secret written.

## HTTP warning

An HTTP issuer emits a one-time Ready warning about missing transport confidentiality. This is expected, not an error.

## Related pages

* [Tested PKIs](../interoperability/tested-pkis.md)
* [Known limitations](../known-limitations.md)
* [Transaction recovery](../guide/transaction-recovery.md)
