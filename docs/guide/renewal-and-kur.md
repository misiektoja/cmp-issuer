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

When a `Certificate` nears expiry cert-manager creates a new `CertificateRequest`. Revision one uses `initialEnrollment`. Later revisions use `renewal`, which follows `initialEnrollment` when omitted: P10CR after P10CR and KUR after IR.

| `renewal` | CMP operation | Workload key access | Server requirement |
| --- | --- | --- | --- |
| `P10CR` or omitted after P10CR | Fresh P10CR | None | Repeat enrollment for the same identity |
| `KUR` or omitted after IR | Certificate-authenticated KUR | Current and staged keys | KUR enabled for the existing certificate |

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

The certificate template repeats the subject of the current certificate exactly as it is encoded there. For a certificate named only in its SANs, that subject is an empty name (NULL-DN), as RFC 9483 requires.

Each KUR also carries the recommended CRMF `oldCertID` control with the current certificate's exact issuer and serial number. This lets a server select the certificate being replaced even after repeated same-key updates have created several certificates for the same subject and public key.

With `rotationPolicy: Always` these are different keys. With `rotationPolicy: Never` the same key makes both proofs and the server profile must allow same-key update.

The keys may be RSA, ECDSA, Ed25519 or ML-DSA. An ML-DSA `tls.key` must be in the seed-only PKCS #8 form, see [Known limitations](../known-limitations.md#ml-dsa).

cmp-issuer rejects KUR before network traffic when the current certificate is expired, its key does not match, its Key Usage extension forbids digital signatures, the staged key does not match the CSR or the subject or SAN values changed. The CA must reject a revoked current certificate.

A certificate originally issued through P10CR or IR can later be renewed through KUR. The enrollment request used for the old certificate does not change the KUR proof or `oldCertID`. Server policy still decides whether that certificate is eligible for key update.

With `requestedValidity: Duration` the KUR template also asks for a validity. See [Requested validity](enrollment.md#requested-validity).

The updated certificate must get a new validity. When the CA returns the `notBefore` and `notAfter` of the certificate being updated, cert-manager finds the renewal time already passed and renews again at once. cmp-issuer rejects such a certificate in `certConf` and fails the request. Configure the CA to compute a new validity on key update or use `renewal: P10CR`. NCM needs a policy setting for this, see [Tested PKIs](../interoperability/tested-pkis.md#certificate-validity).

The selected operation is recorded before the first send and every retry uses the same operation and transaction identifier. A KUR that was sent never changes to another operation.

## Missing or expired current certificate

KUR authenticates with the current certificate. It cannot do so after the `Certificate` Secret was deleted or emptied or after renewals kept failing until the certificate expired. By default the request then fails:

| Current certificate | Result with `renewalFallback: None` |
| --- | --- |
| Secret deleted or without `tls.crt` | Permanent failure that names the Secret and the ways to recover |
| Expired | Permanent `badTime` failure before any CMP traffic |

Set `renewalFallback: InitialEnrollment` to renew with the `initialEnrollment` operation instead:

```yaml
spec:
  protocol:
    initialEnrollment: IR
    renewalFallback: InitialEnrollment
```

An IR issuer then renews with IR. An issuer with `initialEnrollment: P10CR` and `renewal: KUR` renews with P10CR. The fallback goes to `endpoint.url` rather than `renewalUrl` and the issuer credentials protect it. The CMP server must accept an initial enrollment for an identity that already holds a certificate. The old certificate is not revoked.

A Secret that exists falls back only when cert-manager wrote it for the `Certificate`, so its `cert-manager.io/certificate-name` annotation must name the `Certificate`. A Secret written by another tool fails as it does for KUR. A certificate that is not yet valid, does not match its key or no longer matches the CSR identity still renews with KUR and fails with the KUR error.

The choice is made once before the first CMP message. The `CMPTransaction` records the operation in `spec.operation` and the reason in `spec.renewalFallback`, which is `CurrentCertificateMissing` or `CurrentCertificateExpired`. A retry uses the recorded operation even when the certificate returns. A transaction that started as KUR never falls back, so a certificate that expires during an unfinished KUR does not change the operation. The controller logs the fallback and records a `RenewalFallback` Warning Event on the `CertificateRequest`:

```bash
kubectl describe certificaterequest <name> -n <namespace>
```

Without the fallback, set `renewal: P10CR` or delete and recreate the `Certificate`, whose first revision uses `initialEnrollment`.

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

Both profiles accept responses signed by a configured trust anchor when the server omits its
certificate from `extraCerts`. The `RFC9483` profile does not enforce the first-response certificate
presence rule. See [message protection](message-protection.md#what-gets-validated).

## Workload Secret authorization

KUR does not trust `cert-manager.io/private-key-secret-name` by itself. Before reading either key cmp-issuer verifies the controlling `Certificate`, owner UID, immediately previous revision, issuer reference, current output Secret, `status.nextPrivateKeySecretName`, staged Secret owner and label, CSR signature and public-key equality.

The current output Secret must carry cert-manager's `cert-manager.io/certificate-name` annotation naming the owning `Certificate`. cert-manager writes it whenever it stores an issued certificate. A Secret controlled by a different `Certificate` is refused, which matters when cert-manager runs with `--enable-certificate-owner-ref`.

The current and staged Secret UIDs and a digest of their consumed key material are included in the transaction configuration digest. Key rotation during an unfinished KUR stops it before more CMP traffic. A metadata-only write to either Secret leaves the transaction valid.

See [Private-key handling](private-key-handling.md) and [Credential Secret access](../operations/secret-access.md).

## Nokia NCM REST renewal

Some Nokia deployments expose certificate renewal through NCM REST APIs. That path is unrelated to CMP KUR and is unsupported by cmp-issuer.

## Support matrix

| Operation | Status |
| --- | --- |
| P10CR initial enrollment | Implemented |
| P10CR repeat enrollment | Server dependent. Verified against NCM 26.7 for both rotation policies |
| KUR | Implemented for unchanged subject and SANs. Verified against NCM 26.7, EJBCA 9.3.7 and OpenSSL 3.6.3 with both rotation policies |
| IR initial enrollment | Implemented. Verified against NCM 26.7, EJBCA 9.3.7 and OpenSSL 3.6.5 with both protection modes. NCM and EJBCA renewed the IR certificate through KUR |
| Renewal fallback to `initialEnrollment` | Implemented. Verified after the `Certificate` Secret was deleted with IR and P10CR against NCM 26.7 and with IR against EJBCA 9.3.7 in RA mode |
| Nokia NCM REST renewal | Unsupported |

See [Tested PKIs](../interoperability/tested-pkis.md) for server-specific validation and configuration.
