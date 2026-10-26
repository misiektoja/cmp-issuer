# ADR 0005: Renew through initial enrollment when KUR cannot authenticate

* Status: Accepted
* Date: 2026-10-26

## Context

cmp-issuer selects the CMP operation from the cert-manager revision. Revision one uses `initialEnrollment` and later revisions use `renewal`. KUR authenticates with the current certificate, so it cannot succeed after that certificate expired or its Secret was deleted. An expired certificate failed with `badTime` before any CMP traffic. A deleted Secret was a retryable error, so the request stayed Pending and the controller read the Secret every second.

[ADR 0003](0003-kur-renewal.md) rules out changing the operation after the first send. [ADR 0004](0004-ir-initial-enrollment.md) limits IR to revision one.

## Decision

Add `spec.protocol.renewalFallback` with `None` as the default and `InitialEnrollment` as the alternative. The API accepts `InitialEnrollment` only when `renewal` resolves to KUR. The fallback operation is the issuer's `initialEnrollment`, sent to `endpoint.url` under the issuer credentials.

Decide the fallback once before the `CMPTransaction` is recorded, for a revision greater than one whose renewal is KUR. Authorize the owner chain as for KUR, then read the Secret named by `Certificate.spec.secretName`:

* Absent or written by cert-manager for the `Certificate` without a certificate: `CurrentCertificateMissing`
* Written by cert-manager for the `Certificate` with a leaf whose `notAfter` has passed: `CurrentCertificateExpired`
* Anything else, including a Secret written by another tool: KUR, which reports its own error

Only an expired certificate counts. Treating a certificate that expires before the transaction deadline as expired would leave KUR while the current certificate can still prove possession.

Record the operation in `spec.operation` and the reason in `spec.renewalFallback`. On resume the recorded operation is authoritative and the Secret is not classified again. A recorded reason is accepted only for a KUR renewal whose issuer still falls back to the recorded operation. A recorded KUR never falls back.

Allow IR for a later revision only with a fallback reason from that classification or from the record, an issuer that falls back from KUR to IR and the owner-chain and staged-key checks of KUR. IR still reads only the staged key and the issuer credentials protect it. The current Secret is not bound into the configuration digest, because IR does not consume it.

With `renewalFallback: None` a deleted current Secret or one without a certificate fails the request permanently with a message that names the ways to recover.

Log every fallback and record a `RenewalFallback` Warning Event on the `CertificateRequest` when the transaction is created.

## Consequences

Triggering a fallback needs Secret delete permission in the workload namespace or an expired certificate. Creating a `Certificate` for the issuer already yields an initial enrollment under the same credentials, so the fallback adds no capability on the cmp-issuer side.

The CA receives a renewal protected by the issuer credentials instead of the current certificate. A CA that requires KUR for an existing identity refuses it and the request fails with the server's error. The old certificate is not revoked, as with P10CR re-enrollment.

Metrics keep the `renewal` label, which follows the revision rather than the CMP operation.

The fallback is off by default. Existing issuers keep their KUR behavior, except that a deleted current Secret fails the request instead of leaving it Pending.
