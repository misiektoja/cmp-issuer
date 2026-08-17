# Transaction recovery

Asynchronous CMP enrollments can outlive a single controller reconcile. cmp-issuer persists transaction state in a `CMPTransaction` resource owned by the `CertificateRequest`.

## When persistence applies

| Server response | Behavior |
| --- | --- |
| Immediate CP with certificate | Chain recorded, then returned to cert-manager |
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
| `csrDigest` | SHA-256 of the enrolled CSR, in lowercase hexadecimal |
| `issuerRef` | Name, kind and UID of the issuer that served the transaction |
| `operation` | CMP operation, currently `P10CR` |
| `protocolVersion` | CMP protocol version of every message |

**Status** (updated during the transaction):

| Field | Purpose |
| --- | --- |
| `phase` | `Enrolling`, `Polling`, `Confirming` or `Issued` |
| `recipNonce` | Sender nonce to echo in the next request |
| `requestNonce` | Original delayed-request nonce for RFC 9483 section 3.5 |
| `certReqID` | Identifier the server polls against |
| `responseSigner` | DER signer retained when later messages omit identification |
| `polls` | Poll count bounded by `maximumPolls` |
| `issuedChain` | Validated leaf-first chain, recorded before it is returned |
| `completionTime` | When the transaction reached `Issued` |

Inspect transactions:

```bash
kubectl get cmptransactions -A
```

## Controller restart

On restart the signer loads the existing `CMPTransaction` and resumes it rather than starting over. What it does next depends on the recorded phase.

| Recorded phase | Behavior after a restart |
| --- | --- |
| `Enrolling` | Send the enrollment again under the transaction identifier already recorded |
| `Confirming` | Continue confirming the recorded chain, which is already durable |
| `Polling` | Send the next `pollReq` with the recorded nonces and `certReqId` |
| `Issued` | Return the recorded chain without any CMP traffic |

A transaction that fails permanently is deleted. A transaction that reached `Issued` is kept and is garbage collected with its `CertificateRequest`, so a completed enrollment stays visible in `kubectl get cmptransactions`.

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

If the controller stops after sending the enrollment but before receiving the response, the outcome is unknown. The server may have issued a certificate that never arrived. Because the transaction identifier is pinned in `spec.transactionID` before the message reaches the network, the next reconcile enrolls again under **that same identifier** rather than generating a new one.

**The purpose is to make a duplicate certificate impossible, not to recover the lost one.** On both tested servers the repeat is refused rather than answered from the existing transaction:

| Server | Answer to a repeated transaction identifier |
| --- | --- |
| Nokia NCM 26.7 | Protected `error`, `rejection`, failInfo **`transactionIdInUse`** |
| EJBCA CE 9.3.7 | Protected `error`, `rejection`, failInfo **`badRequest`**, because issuance already moved the end entity to `GENERATED` |

Neither server issued a second certificate. Both answers are protected and echo the transaction identifier and nonce, so the refusal is authenticated rather than guessed. The request then **fails permanently**, and cert-manager enrolls again under a new transaction identifier. The certificate created by the lost response is orphaned and never used, because the controller never received it.

Reusing the recorded identifier rather than generating a fresh one is what makes this outcome reliable. A new identifier presents the retry to the server as an unrelated enrollment, which is accepted and yields a second certificate.

### Crash between issuance and storage

If the controller stops after the server issued the certificate but before cert-manager stored it, the recorded chain is returned on the next reconcile. No second enrollment is sent and no certificate is lost.

### Credential rotation mid-transaction

Rotated PBM or signature Secrets invalidate in-flight protection. The transaction fails within `maximumDuration`. ResourceVersions are not recorded.

## Delayed confirmation

After CP succeeds the signer records the validated chain, then sends `certConf`. A server may answer `waiting` instead of `pkiConf`, which RFC 9483 section 4.4 allows for every operation. The transaction then enters `Confirming` and is polled with `pollReq` under the same `spec.transaction` limits as a delayed enrollment.

Because the chain is recorded **before** `certConf` is sent, a restart at any point during confirmation resumes it from the recorded state. The certificate is never enrolled twice and never discarded because the acknowledgement was slow.

Configure `protocol.confirmation: Implicit` on servers that grant implicit confirmation to skip this exchange entirely.

## Related pages

* [Architecture](../architecture.md)
* [Known limitations](../known-limitations.md)
* [Enrollment](enrollment.md)
