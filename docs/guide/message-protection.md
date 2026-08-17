# Message protection

Every CMP request and response must carry PKIProtection. cmp-issuer supports two protection modes configured in `spec.protection.type`.

## Modes

| Mode | RFC basis | Credential |
| --- | --- | --- |
| `PasswordBasedMac` | RFC 4210 PasswordBasedMac | Shared reference and secret |
| `Signature` | RFC 4210 certificate-based protection | Bootstrap certificate and private key |

Unprotected CMP messages are rejected. Transport encryption does not replace message protection.

## Outbound protection

The signer protects:

* P10CR enrollment requests
* `pollReq` messages during asynchronous transactions
* `certConf` confirmation messages when explicit confirmation is configured

Protection uses the issuer credential loaded from the authorized Secret.

## Inbound validation

Before accepting a certificate the signer validates:

* Response PKIProtection algorithm and integrity
* Signer trust against `spec.cmpTrust`
* Transaction identifier and nonces
* P10CR `certReqId` against policy
* Exactly one `CertResponse` in CP
* Issued public key matches the CSR
* Leaf-first chain validates against CMP trust

Protected error responses from the server are verified the same way. A verification failure fails the `CertificateRequest` with no certificate stored.

## Confirmation signer retention

Some servers omit `extraCerts` and `senderKID` from `pkiConf`. cmp-issuer retains the signer certificate already validated when `cp` was accepted and verifies the linked `pkiConf` against that certificate. Invalid confirmation protection is still rejected.

See [Tested PKIs](../interoperability/tested-pkis.md) for NCM behavior.

## Algorithm policy

PasswordBasedMac defaults:

| Parameter | Value |
| --- | --- |
| OWF | SHA-256 |
| MAC | HMAC-SHA-256 |
| Iteration count | 1024 |

Downgrade to weaker algorithms is not supported. PBMAC1 is planned.

## Related pages

* [PasswordBasedMac](password-based-mac.md)
* [Signature protection](signature-protection.md)
* [CMP response trust](cmp-response-trust.md)
