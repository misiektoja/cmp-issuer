# Transaction recovery

Asynchronous CMP enrollments can outlive a single controller reconcile. cmp-issuer persists transaction state in a `CMPTransaction` resource owned by the `CertificateRequest`.

## When persistence applies

| Server response | Behavior |
| --- | --- |
| Immediate CP with certificate | Short-lived transaction, deleted on success |
| `waiting` on enrollment | Poll loop; state persisted across restarts |
| `waiting` on delayed `certConf` | Inline poll up to one minute; **not** persisted in `CMPTransaction` |

## CMPTransaction fields

**Spec** (written before the first CMP message):

| Field | Purpose |
| --- | --- |
| `certificateRequestName` | Owning request |
| `certificateRequestUID` | Detects name reuse |
| `transactionID` | CMP transaction identifier for every message |
| `deadline` | Absolute transaction expiry |

**Status** (updated during the transaction):

| Field | Purpose |
| --- | --- |
| `phase` | `Enrolling` or `Polling` |
| `recipNonce` | Sender nonce to echo in the next request |
| `requestNonce` | Original delayed-request nonce for RFC 9483 section 3.5 |
| `certReqID` | Identifier the server polls against |
| `responseSigner` | DER signer retained when later messages omit identification |
| `polls` | Poll count bounded by `maximumPolls` |

Inspect in-flight work:

```bash
kubectl get cmptransactions -A
```

## Controller restart

On restart the signer loads the existing `CMPTransaction` and resumes polling instead of sending a second enrollment with a new transaction identifier.

## Transaction limits

Configure in `spec.transaction`:

```yaml
spec:
  transaction:
    maximumDuration: 10m
    minimumPollInterval: 1s
    maximumPollInterval: 5m
    maximumPolls: 60
```

Poll intervals honor the server `pollRep` hint clamped to the minimum and maximum. Missing hints use `minimumPollInterval`.

## Ambiguous failure modes

### Crash between send and response

If the controller stops after recording a transaction but before receiving the enrollment response, the outcome is unknown. The next reconcile re-sends enrollment under the **same** transaction identifier. Servers that enforce transaction identifiers reject duplicate issuance.

The exact protected outbound DER is **not** persisted, so the retry rebuilds the message rather than replaying identical bytes. See [Known limitations](../known-limitations.md).

### Credential rotation mid-transaction

Rotated PBM or signature Secrets invalidate in-flight protection. The transaction fails within `maximumDuration`. ResourceVersions are not recorded.

## Delayed confirmation

After CP succeeds the signer may send `certConf` and receive `waiting` instead of `pkiConf`. RFC 9483 section 4.4 applies. The issuer polls inline for up to one minute. Configure `protocol.confirmation: Implicit` on servers that grant implicit confirmation to skip this exchange.

## Related pages

* [Architecture](../architecture.md)
* [Known limitations](../known-limitations.md)
* [Enrollment](enrollment.md)
