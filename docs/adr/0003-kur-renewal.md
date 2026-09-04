# ADR 0003: Select renewal operation explicitly

* Status: Accepted
* Date: 2026-08-24

## Context

cert-manager renewal describes when a new certificate is needed. It does not select a CMP request body. cmp-issuer originally sent a fresh P10CR for every revision. That works only when the server profile allows repeat enrollment for the same identity.

CMP KUR is a different operation. RFC 9483 requires the still-valid certificate being updated to protect the request. CRMF proof of possession must be made with the requested key. This means a rotating renewal uses two keys while same-key renewal uses one key for both proofs.

A certificate's original enrollment syntax does not prevent a later KUR. A P10CR-issued certificate can authenticate KUR when the server can find it and its profile allows key update. EJBCA client mode was validated with a P10CR endpoint for revision one and a separate certificate-authenticated KUR endpoint for later revisions. Nokia NCM was validated with both operations on one endpoint.

## Decision

Add `spec.protocol.renewal` with values `P10CR` and `KUR`. `P10CR` remains the default. Initial issuance remains P10CR in both modes.

Add optional `spec.endpoint.renewalUrl`. When set, KUR uses this URL while P10CR uses `spec.endpoint.url`. When omitted, both operations use the primary URL. This supports servers such as EJBCA where initial enrollment and key update use separate CMP aliases.

Select the operation before creating a `CMPTransaction` and persist it in `spec.operation`. Never fall back from KUR to P10CR after a send. A timeout can be ambiguous and changing operations could issue another certificate.

Default response validation to `spec.protocol.validationProfile: Interoperable`. KUP `caPubs` and
`extraCerts` are untrusted chain-building candidates under this profile. They never extend configured
CMP trust. Add `RFC9483` as a bundled receiver profile that pins P10CR CP `certReqId` to `-1`, requires
MAC protection throughout a MAC-protected operation and requires KUP `caPubs` absent. Keep focused
controls for deployments that need only one rule.

Authorize workload key reads through cert-manager state rather than through an annotation alone. The signer validates all of the following before it reads either workload Secret:

* A controlling `cert-manager.io/v1` `Certificate` owner with the exact name and UID
* A renewal revision that immediately follows `Certificate.status.revision`
* The same issuer reference on the `Certificate`
* The current Secret selected by `Certificate.spec.secretName`
* The staged Secret selected by both `Certificate.status.nextPrivateKeySecretName` and the CertificateRequest annotation
* The staged Secret's controlling owner and cert-manager next-key label
* The current certificate and key pair
* The staged private key and signed CSR public key

KUR is rejected locally when the old certificate is not currently valid, its Key Usage extension forbids digital signatures or the CSR changes the subject or subject alternative names.

Bind unfinished KUR state to the UID and a digest of the consumed key material of the current and staged workload Secrets in the transaction configuration digest. A key-material change stops the transaction before more CMP traffic, while a metadata-only write by another controller does not.

## Consequences

KUR needs `get` access to the owning `Certificate` and `get` access to both workload Secrets. Certificate access is cluster-wide but read-only. Secret access remains namespace bounded through the existing credential-reader RoleBindings. A `CMPClusterIssuer` using KUR therefore needs each workload namespace added to `credentialNamespaces` or bound manually.

P10CR keeps its previous private-key boundary and never reads workload Secrets. Existing issuers keep renewing through P10CR re-enrollment unless an operator selects KUR.

Same-key KUR remains server-profile dependent. The server is also responsible for checking revocation of the old certificate.

IR is not part of this decision. It may reuse this authorization boundary in a later release.
