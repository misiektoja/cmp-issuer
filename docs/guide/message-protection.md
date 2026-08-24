# Message protection

Every CMP request and response must carry PKIProtection. Unprotected messages are rejected, and
transport encryption does not replace message protection, so an HTTP endpoint is still authenticated.

cmp-issuer supports two protection modes, configured in `spec.protection.type`:

| Mode | RFC basis | Credential | Use it when |
| --- | --- | --- | --- |
| `PasswordBasedMac` | RFC 4210 PasswordBasedMac | Shared reference and secret | The server issued you an enrollment code |
| `Signature` | RFC 4210 certificate-based protection | Bootstrap certificate and private key | The device or workload already holds an identity the server trusts |

The selected mode protects initial P10CR and compatibility P10CR renewal. Response validation is
identical for both modes.

KUR always uses the current workload certificate and private key for request protection as required by
the CMP profile. This replaces the configured bootstrap or shared-secret request protection only for
the KUR exchange. The configured CMP trust policy still validates every response.

## PasswordBasedMac

### Secret format

Create a Secret in the issuer's namespace:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cmp-pbm-credentials
type: Opaque
stringData:
  reference: "<server-assigned-reference>"
  secret: "<shared-secret>"
```

Default keys are `reference` and `secret`. Override them with `referenceKey` and `secretKey`.

### Issuer configuration

```yaml
spec:
  protection:
    type: PasswordBasedMac
    passwordBasedMac:
      secretRef:
        name: cmp-pbm-credentials
      referenceKey: reference
      secretKey: secret
      algorithm:
        owf: SHA256
        mac: HMACSHA256
        iterationCount: 1024
```

### Algorithm fields

| Field | Allowed values | Default |
| --- | --- | --- |
| `owf` | `SHA256` | `SHA256` |
| `mac` | `HMACSHA256` | `HMACSHA256` |
| `iterationCount` | 100-1048575 | 1024 |

These must match the server's PBM profile. cmp-issuer does not negotiate weaker algorithms, and PBMAC1
is planned rather than implemented.

### Response protection

Many servers sign every response regardless of how the request was protected. EJBCA does this on any
CMP alias left at its own default of `responseprotection` `signature`. RFC 9483 section 5 permits that
substitution, so `spec.protocol.macResponseProtection` defaults to `AllowSignature` and both a
MAC-protected and a signed response are accepted.

Accepting a signature does not weaken the response to an unauthenticated one. The signer must chain to
`spec.cmpTrust.caSecretRef` and the response sender must name `spec.protocol.recipient`, which is the
same authority check a `Signature` issuer already relies on for every response it receives.

Require MAC-based protection throughout with:

```yaml
spec:
  protocol:
    macResponseProtection: Strict
```

Then the shared secret authenticates the response as well as the request, and a signature is rejected
however well it verifies. Set this where the CMP trust anchor is shared with authorities that must not
be able to answer for the recipient, or to conform to a profile that requires one protection type for a
whole PKI management operation. Confirm the server protects its answers with the shared secret before
turning it on, since a server that signs them will have issued the certificate before the response is
rejected.

### Server setup

The reference and secret must exist on the CMP server before enrollment. cmp-issuer does not register
credentials over CMP.

EJBCA client mode treats the enrollment code as a one-time credential. After issuance the end entity
moves to `GENERATED` and refuses further requests until an administrator resets it. See
[Tested PKIs](../interoperability/tested-pkis.md).

## Signature protection

### Secret format

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cmp-signature-credentials
type: kubernetes.io/tls
stringData:
  tls.crt: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  tls.key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ... optional intermediate chain ...
    -----END CERTIFICATE-----
```

| Key | Required | Purpose |
| --- | --- | --- |
| `tls.crt` | yes | Protection certificate (default `certificateKey`) |
| `tls.key` | yes | Protection private key (default `privateKeyKey`) |
| `ca.crt` | optional | Intermediate chain sent in `extraCerts` (default `chainKey`) |

Custom key names are set with `certificateKey`, `privateKeyKey` and `chainKey`.

### Issuer configuration

```yaml
spec:
  protection:
    type: Signature
    signature:
      secretRef:
        name: cmp-signature-credentials
      certificateKey: tls.crt
      privateKeyKey: tls.key
      chainKey: ca.crt
```

### extraCerts layout

cmp-issuer sends the protection end-entity certificate first, followed by the configured intermediates.
Some servers resolve the signing certificate from `extraCerts` using `senderKID`, and Nokia NCM requires the
end-entity certificate to appear there for P10CR.

### EJBCA client mode

EJBCA resolves the authenticating certificate from its own database, so the credential needs only
`tls.crt` and `tls.key` and `chainKey` may be omitted.

Client mode enrolls only the identity that owns the authenticating certificate, and the requested
subject DN must match the registered end entity. A signature-protected issuer therefore issues for its
bootstrap identity rather than arbitrary workload names, unless the server profile allows otherwise.

## What gets protected

The signer protects every message it sends:

* P10CR enrollment requests
* KUR requests with the current workload certificate
* `pollReq` messages during asynchronous transactions
* `certConf` confirmation messages when explicit confirmation is configured

## What gets validated

Before accepting a certificate the signer validates:

* Response PKIProtection algorithm and integrity
* Signer trust against `spec.cmpTrust`
* That the response sender names the configured `recipient`
* Transaction identifier and nonces
* P10CR `certReqId` against policy or KUR `certReqId` fixed at `0`
* Exactly one `CertResponse` in CP or KUP and no `caPubs` in KUP
* That the issued public key matches the CSR
* A leaf-first chain that validates against CMP trust

Protected error responses are verified the same way. A verification failure fails the
`CertificateRequest` and stores no certificate.

### Confirmation signer retention

Some servers omit `extraCerts` and `senderKID` from `pkiConf`. cmp-issuer retains the signer certificate
already validated when `cp` was accepted and verifies the linked `pkiConf` against it. Invalid
confirmation protection is still rejected. See [Tested PKIs](../interoperability/tested-pkis.md) for Nokia NCM
behavior.

## Credential rotation

Credentials are reloaded from the Secret on every reconcile. Rotating a Secret during an open
transaction invalidates in-flight protection and the transaction fails within `maximumDuration`. The
transaction configuration digest records the UID and resourceVersion of every referenced credential
Secret. For KUR it also records both workload Secrets. cmp-issuer stops the unfinished transaction
before sending more CMP traffic when any of those values changes. See [Known limitations](../known-limitations.md).

## Related pages

* [CMP response trust](cmp-response-trust.md)
* [Enrollment](enrollment.md)
* [Tested PKIs](../interoperability/tested-pkis.md)
