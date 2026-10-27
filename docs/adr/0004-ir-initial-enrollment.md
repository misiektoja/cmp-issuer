# ADR 0004: Add IR initial enrollment

* Status: Accepted, amended by [ADR 0005](0005-renewal-fallback.md)
* Date: 2026-10-26

## Context

cert-manager generates the workload key and signs a PKCS #10 CSR. P10CR forwards that CSR, so the controller never needs the key. Many CMP server profiles, including Lightweight CMP in RFC 9483, expect a CRMF IR for initial enrollment and KUR for renewal.

CRMF proof of possession must be signed with the requested key, which only cert-manager's staged private-key Secret holds. A CRMF certificate template can also ask for a validity period, which a PKCS #10 request cannot carry.

## Decision

Accept `IR` in `spec.protocol.initialEnrollment`. Build the CRMF template from the CSR subject, public key and extensions. The subject is the NULL-DN when the CSR names the entity only in its SANs, as RFC 9483 section 4.1.1 requires. Sign proof of possession with the staged key. Protect the message with the issuer credentials, as for P10CR. Send `certReqId` `0` and require it in the IP.

Use IR only for revision one of a cert-manager `Certificate`. Authorize the staged key read with the ownership checks of [ADR 0003](0003-kur-renewal.md), without the current Secret, which revision one does not have. A `CertificateRequest` without cert-manager revision state cannot use IR and fails before CMP traffic.

Make an omitted `spec.protocol.renewal` follow `initialEnrollment`: P10CR after P10CR and KUR after IR. A server profile that accepts IR expects KUR for renewal. The CRD carries no default for `renewal`, so the controller can tell the omission from an explicit `P10CR`.

Add `spec.protocol.requestedValidity` with `Omit` as the default and `Duration` as the alternative. `Duration` asks in each IR and KUR for a `notAfter` of the transaction start plus the `CertificateRequest` duration. The API rejects `Duration` when neither IR nor KUR can be selected.

## Consequences

IR reads the staged workload Secret, so a `CMPClusterIssuer` using IR needs the same RoleBinding in each workload namespace as one using KUR.

Issuers that enroll with IR renew through KUR by default. A CA can keep the validity of the old certificate on key update, which makes cert-manager renew again at once, so the controller rejects a KUR certificate whose `notBefore` and `notAfter` equal those of the certificate it updates. Issuers that enroll with P10CR keep renewing through P10CR re-enrollment when `renewal` is omitted. `requestedValidity` defaults to `Omit`, so no existing request gains a validity.

The CA decides the validity it grants. A request for a validity the CA shortens or ignores still succeeds unless the CA reports `grantedWithMods` and `spec.policy.grantedModifications` is `Reject`.
