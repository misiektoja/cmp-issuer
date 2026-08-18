# ADR 0002: build on issuer-lib and pin it

* Status: accepted for initial development

## Context

An external issuer has to reconcile `CertificateRequest` resources correctly before it does anything
with CMP. That means honoring cert-manager approval, initializing and patching status conditions with
server-side apply, classifying failures into permanent and retryable, requeueing with backoff, emitting
events, and doing the same again for a cluster-scoped issuer type. Every one of those is a place to be
subtly wrong in ways that only show up under load or during upgrades.

`github.com/cert-manager/issuer-lib` implements exactly that layer, and it is maintained by the
cert-manager project itself. Its README states that the API is still subject to change and advises
using it for experimentation, so building on it is a deliberate trade rather than a default.

## Decision

Use issuer-lib for the reconciliation layer and pin it to an exact version, currently `v0.12.0`.
`CMPIssuer` and `CMPClusterIssuer` implement its `Issuer` interface, and enrollment is reached through
its `Sign` and `Check` callbacks. The Kubernetes `CertificateSigningRequest` controller it also offers
is deliberately disabled.

Unlike the CMP library in [ADR 0001](0001-cmp-library.md), issuer-lib is **not** isolated behind
project-owned interfaces. Its types appear directly in the signer contract: the `Sign` and `Check`
signatures, `PermanentError`, `PendingError` and `IssuerError`, `CertificateRequestObject`, and the
`Issuer` interface our API types implement. Wrapping all of that would reimplement the library's
contract in order to hide it, which buys nothing.

The CMP protocol layer carries none of it. `internal/protocol` has no issuer-lib import, so the part of
this project that is worth reusing elsewhere is not bound to the reconciliation layer.

## Consequences

An upgrade is a code change, not a version bump. Treat every issuer-lib upgrade as a behavioral change:
review the changelog for contract changes, run the full check suite, and complete one live enrollment
against each tested CMP server before accepting it.

Defects in the reconciliation layer are ours to detect and report. One is already known. In `v0.12.0`
the `CertificateRequest` helper decides `IsDenied` by looking for a `Ready=False` condition with reason
`Denied`, rather than for cert-manager's `Denied` condition type, so a request that an approver has
denied and nothing else has touched is treated as neither approved nor denied and is ignored. The
library never records the terminal condition it intends to record for that request. cert-manager's own
issuing controller acts on the `Denied` condition directly, so the `Certificate` still fails promptly
and no CMP message is ever sent, which is why this is a reporting gap rather than a correctness or
safety problem. [Troubleshooting](../operations/troubleshooting.md#denied-or-unapproved-requests)
describes what an operator sees.

The alternative, reconciling `CertificateRequest` resources by hand, was rejected. It moves the approval
gate, the status patching and the retry classification into this project, where they would get less
review than they do upstream, and it would not have prevented the defect above from existing somewhere.
