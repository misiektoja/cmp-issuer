# Renewal with P10CR or KUR

cert-manager decides when to renew a `Certificate`. cmp-issuer decides which CMP operation performs that renewal through `spec.protocol.renewal`.

```yaml
spec:
  endpoint:
    url: https://ca.example.test/cmp/initial
    renewalUrl: https://ca.example.test/cmp/key-update
  protocol:
    initialEnrollment: P10CR
    renewal: KUR
```

`renewalUrl` is optional. Omit it when one CMP endpoint accepts both P10CR and KUR.

## cert-manager renewal

When a `Certificate` nears expiry cert-manager creates a new `CertificateRequest`. Revision one always uses P10CR. Later revisions use the configured renewal operation.

| `renewal` | CMP operation | Workload key access | Server requirement |
| --- | --- | --- | --- |
| `P10CR` or omitted | Fresh P10CR | None | Repeat enrollment for the same identity |
| `KUR` | Certificate-authenticated KUR | Current and staged keys | KUR enabled for the existing certificate |

## P10CR compatibility renewal

P10CR is the default for compatibility. It was exercised against Nokia NCM 26.7 through cert-manager with both values of `privateKey.rotationPolicy`:

| `rotationPolicy` | What the renewal sends | Result |
| --- | --- | --- |
| `Always` | A new key, so a new public key in the CSR | New certificate, new serial |
| `Never` | The existing key, so the same public key in the CSR | New certificate, new serial |

Each renewal is a new CMP transaction with a fresh identifier. It is not a retransmission of the earlier transaction. The controller reads no workload private key in this mode.

## True KUR renewal

KUR proves two things before the server updates the certificate:

1. The current valid certificate and private key protect the CMP message.
2. The requested private key signs CRMF proof of possession.

With `rotationPolicy: Always` these are different keys. With `rotationPolicy: Never` the same key makes both proofs and the server profile must allow same-key update.

cmp-issuer rejects KUR before network traffic when the current certificate is expired, its key does not match, its Key Usage extension forbids digital signatures, the staged key does not match the CSR or the subject or SAN values changed. The CA must reject a revoked current certificate.

A certificate originally issued through P10CR can later be renewed through KUR. The enrollment request used for the old certificate does not change the KUR proof. Server policy still decides whether that certificate is eligible for key update.

No automatic KUR-to-P10CR fallback exists. The selected operation is recorded before the first send and every retry uses the same operation and transaction identifier.

## Response validation profiles

`spec.protocol.validationProfile` defaults to `Interoperable`. This accepts KUP `caPubs` because CMP
servers including EJBCA and Nokia NCM can legitimately be configured to deliver CA certificates there.
Those certificates are untrusted chain candidates only. They cannot add a trust root and the issued
chain must still terminate at `spec.cmpTrust`.

Use the RFC 9483 receiver rules for the implemented operations with:

```yaml
spec:
  protocol:
    validationProfile: RFC9483
```

This pins P10CR CP `certReqId` to `-1`, requires MAC-based responses throughout a MAC-protected
operation and requires KUP `caPubs` absent. Tested NCM and EJBCA versions return P10CR `certReqId` `0`,
so the complete profile rejects their initial enrollment behavior. Use the default profile with a
focused setting when only one rule is required:

```yaml
spec:
  protocol:
    kurResponseCaPubs: RequireAbsent
```

The focused values are `kurResponseCaPubs: Accept | RequireAbsent`,
`macResponseProtection: AllowSignature | Strict` and `p10crResponseCertReqId: -1 | 0`.

## Workload Secret authorization

KUR does not trust `cert-manager.io/private-key-secret-name` by itself. Before reading either key cmp-issuer verifies the controlling `Certificate`, owner UID, immediately previous revision, issuer reference, current output Secret, `status.nextPrivateKeySecretName`, staged Secret owner and label, CSR signature and public-key equality.

The current and staged Secret UID and resourceVersion values are included in the transaction configuration digest. Rotation during an unfinished KUR stops it before more CMP traffic.

See [Private-key handling](private-key-handling.md) and [Credential Secret access](../operations/secret-access.md).

## Nokia NCM REST renewal

Some Nokia deployments expose certificate renewal through NCM REST APIs. That path is unrelated to CMP KUR and is unsupported by cmp-issuer.

## Support matrix

| Operation | Status |
| --- | --- |
| P10CR initial enrollment | Implemented |
| P10CR repeat enrollment | Server dependent. Verified against NCM 26.7 for both rotation policies |
| KUR | Implemented for unchanged subject and SANs. Verified against NCM 26.7, EJBCA 9.3.7 and OpenSSL 3.6.3 with both rotation policies |
| IR (CRMF) | Planned |
| Nokia NCM REST renewal | Unsupported |

See [Tested PKIs](../interoperability/tested-pkis.md) for server-specific validation and configuration.
