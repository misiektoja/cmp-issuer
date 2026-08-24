# Known limitations

Behavior to plan around in the current release. Each item states what is not covered and the failure it can produce.

## Transaction durability

cmp-issuer records the operation, transaction identifier, issuer and Secret configuration identity plus the issued chain in `CMPTransaction`, so an asynchronous enrollment survives a controller restart and an interrupted attempt resumes under its original transaction identifier rather than starting a new one. The gaps below remain.

### A lost enrollment response cannot be recovered

If the controller stops after sending an enrollment and the response never arrives, retrying under the recorded transaction identifier reliably prevents a second certificate but does not retrieve the first one. Neither tested server answers the repeat from its existing transaction: Nokia NCM 26.7 refuses it with `transactionIdInUse` and EJBCA CE 9.3.7 refuses it with `badRequest`. The `CertificateRequest` fails and cert-manager enrolls again under a new transaction identifier, which succeeds. The certificate the server issued for the lost response is orphaned and counts against any issuance quota or audit trail the certificate authority keeps.

### Coarse progress reporting

`CMPTransaction.status.phase` reports `Enrolling`, `Polling`, `Confirming` or `Issued`, so `kubectl get cmptransactions` shows less detail than the underlying message flow.

### Completed transactions are retained

A transaction that obtained a certificate keeps its record, including the issued chain, so that a restart before cert-manager stores the certificate does not enroll a second one. The record is removed only when the owning `CertificateRequest` is garbage collected, so `kubectl get cmptransactions` lists completed transactions next to in-flight ones.

## Protocol and product scope

| Limitation | Status |
| --- | --- |
| IR and CRMF | Planned |
| KUR with a changed subject or SAN | Unsupported by design. Use P10CR where the server permits re-enrollment or wait for planned CR support |
| KUR after the old certificate expires | Unsupported by RFC profile requirements. Renew while it is still valid |
| PBMAC1 | Planned |
| mTLS to the CMP endpoint | Planned |
| CMPv3 | Planned |
| Revocation over CMP | Planned |
| Kubernetes CSR signing | Unsupported by design |
| Broad CMP compatibility | Not claimed |

See [Support matrix](support-matrix.md).

## Dependencies

The CMP encoding layer is a pre-v1 library kept behind project-owned interfaces and maintained by this project's author. It remains security sensitive, so responses are validated independently of it. See [ADR 0001](adr/0001-cmp-library.md).

## API stability

`certmanager.misiektoja.github.io/v1alpha1` may change before a stable version.

## Related pages

* [Transaction recovery](guide/transaction-recovery.md)
* [Threat model](security/threat-model.md)
