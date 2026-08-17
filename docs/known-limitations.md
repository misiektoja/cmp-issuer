# Known limitations

Behavior to plan around in the current release. Each item states what is not covered and the failure it can produce.

## Transaction durability

cmp-issuer records enough state in `CMPTransaction` to resume an asynchronous enrollment after a controller restart. It does not keep a full record of the exchange.

### Enrollment messages are rebuilt rather than replayed

The protected outbound message is not stored before it is sent. After a crash or an ambiguous HTTP timeout the controller rebuilds the enrollment request instead of resending identical bytes. The CMP transaction identifier is reused, so a server that enforces transaction identifiers still prevents a second issuance, but it cannot tell a lost response apart from a new attempt.

### Limited transaction detail

The CSR digest, issuer UID, CMP operation, protocol version and the final validated chain are not written to `CMPTransaction`. After a restart, diagnosis relies on the `CertificateRequest` and on server-side logs rather than on stored transaction detail.

### Credential rotation is not detected

Credential Secret versions are not recorded when a transaction begins. Rotating a PasswordBasedMac or signature Secret while a transaction is open changes the protection material without an explicit signal. The transaction fails when the server rejects the new protection or when `maximumDuration` elapses, not at the moment of rotation.

### Coarse progress reporting

`CMPTransaction.status.phase` reports only `Enrolling` or `Polling`, so `kubectl get cmptransactions` shows less detail than the underlying message flow. Confirmation and delayed confirmation are handled without a separate phase.

### Delayed confirmation is not resumable

When a server answers `certConf` with `waiting`, the issuer polls inline for up to one minute and records nothing in `CMPTransaction`. A controller restart inside that window can fail the `CertificateRequest` even though the certificate was already issued. Enable implicit confirmation on servers that grant it to avoid the window.

## Protocol and product scope

| Limitation | Status |
| --- | --- |
| IR and CRMF | Planned |
| KUR | Planned |
| PBMAC1 | Planned |
| mTLS to the CMP endpoint | Planned |
| CMPv3 | Planned |
| Revocation over CMP | Planned |
| Kubernetes CSR signing | Unsupported by design |
| Broad CMP compatibility | Not claimed |

See [Support matrix](support-matrix.md).

## Dependencies

The CMP encoding layer is a pre-v1 dependency kept behind project-owned interfaces. It remains security sensitive, so responses are validated independently of it. See [ADR 0001](adr/0001-cmp-library.md).

## API stability

`certmanager.misiektoja.github.io/v1alpha1` may change before a stable version.

## Related pages

* [Transaction recovery](guide/transaction-recovery.md)
* [Threat model](security/threat-model.md)
