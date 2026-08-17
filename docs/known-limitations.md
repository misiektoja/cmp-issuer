# Known limitations

Explicit gaps in the first delivery. Each item states the failure mode it leaves open.

## Phase 4 transaction persistence

The specification asked for more durable state than is implemented today. The controller persists enough to resume asynchronous enrollments across restarts, but not full forensic replay.

### Outbound DER not persisted

**Gap:** The exact protected outbound DER is not stored in a controller-owned Secret before sending.

**Failure mode:** After an ambiguous HTTP timeout or crash between send and response the controller rebuilds the enrollment message rather than replaying identical bytes. The transaction identifier is reused. Servers that treat rebuilt messages differently from true replays may accept or reject unpredictably. Servers that enforce transaction identifiers prevent duplicate issuance but cannot distinguish network loss from a new enrollment attempt.

### Enrollment context not persisted

**Gap:** CSR hash, issuer UID, CMP operation, protocol version and the final validated chain are not stored on `CMPTransaction`.

**Failure mode:** Post-mortem analysis and cross-check after restart rely on the live `CertificateRequest` and server logs, not on persisted transaction artifacts.

### Credential rotation not detected

**Gap:** Credential Secret resourceVersions are not recorded when a transaction starts.

**Failure mode:** Rotating a PBM or signature Secret during an open transaction changes protection material without an explicit detection event. The transaction fails when the server rejects the new protection or when `maximumDuration` elapses, not immediately at rotation time.

### Simplified phase model

**Gap:** `CMPTransaction.status.phase` has two values, `Enrolling` and `Polling`, rather than a finer-grained state machine.

**Failure mode:** Operators see less granular progress in `kubectl get cmptransactions` than a multi-state design would provide. Reconciliation logic still handles confirmation and delayed confirmation internally.

### Delayed confirmation not persisted

**Gap:** When the server delays `pkiConf` after `certConf`, polling is inline for up to one minute and is not recorded in `CMPTransaction`.

**Failure mode:** A controller restart during delayed confirmation may fail the request even though the certificate was already issued at the CMP layer. Configure implicit confirmation on servers that support it to avoid this window.

## Protocol and product scope

| Limitation | Status |
| --- | --- |
| IR and CRMF | Planned |
| KUR | Planned |
| PBMAC1 | Planned |
| mTLS to CMP endpoint | Planned |
| CMPv3 | Planned |
| Revocation over CMP | Planned |
| Kubernetes CSR signing | Unsupported by design |
| Broad CMP compatibility | Not claimed |

See [Support matrix](support-matrix.md).

## Dependencies

go-pkicmp is pre-v1 and lightly adopted. It remains isolated behind project-owned interfaces but is still a security-sensitive parser dependency. See [go-pkicmp review](dependencies/go-pkicmp-review.md).

## API stability

`certmanager.misiektoja.github.io/v1alpha1` may change before a stable version.

## issuer-lib denial detection

issuer-lib `IsDenied` tests for `Ready=False` with reason `Denied` rather than a `Denied` condition type. A freshly denied request may appear neither approved nor denied in helper logic. cmp-issuer still sends no CMP traffic for denied requests.

Consider reporting upstream to cert-manager issuer-lib.

## Related pages

* [Transaction recovery](guide/transaction-recovery.md)
* [Threat model](security/threat-model.md)
