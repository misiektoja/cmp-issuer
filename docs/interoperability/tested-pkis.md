# Tested PKIs

cmp-issuer has completed protected P10CR enrollments through real cert-manager `Certificate` resources against the servers below. Compatibility for any other server depends on its CMP profile, enabled operations, algorithms, endpoint structure and authentication policy.

## Nokia NCM 26.7 / Insta Certifier 7.20

| Item | Value |
| --- | --- |
| Product | [Nokia NCM 26.7](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) |
| CMP implementation | Insta Certifier 7.20 |
| Protection tested | PasswordBasedMac, certificate signature |
| Confirmation | Explicit `certConf` and protected `pkiConf` |

### P10CR certReqId

NCM returns `certReqId` `0` in P10CR CP responses. The default issuer accepts `-1` or `0`. Pinning `-1` fails permanently.

### Signer identification in pkiConf

NCM omits `extraCerts` and `senderKID` from `pkiConf`. Its `cp` is signature protected and carries the signer in `extraCerts`. cmp-issuer retains the signer validated when `cp` was accepted and verifies the linked `pkiConf` against that certificate. Invalid confirmation protection is still rejected.

### P10CR extraCerts requirement

NCM resolves the signing certificate from `extraCerts` using `senderKID`. cmp-issuer sends the protection certificate followed by configured intermediates. NCM accepts this layout.

The vendor `ssh-cmpclient P10CR` sends only the issuing chain and omits the end-entity certificate its own `senderKID` names, so NCM answers with a header protection failure. That rejection reflects the vendor client message, not the server profile.

### Protected error responses

NCM protected error messages verify against configured CMP trust anchors, so a rejection is reported to cert-manager as an authenticated failure rather than a transport error.

### Retransmitted enrollment

NCM answers a repeat of an enrollment it already accepted with a protected error carrying failInfo `transactionIdInUse`, and issues no second certificate. It does not return the certificate from the original transaction.

NCM keys this on the transaction ID rather than on the message content, so any repeat under an identifier it has already answered draws the same protected error regardless of how the message is built. Pinning the transaction ID across a retry is therefore what prevents a duplicate certificate on this server.

### Renewal through repeat P10CR

NCM re-enrolls an identity it has already certified. A cert-manager renewal was exercised for both values of `privateKey.rotationPolicy`: with `Always`, where the CSR carries a new public key, and with `Never`, where it carries the key the first certificate already used. Both produced a new certificate with a new serial number, and the server recorded each as its own transaction answered with a certificate response.

This is P10CR re-enrollment rather than KUR. It differs from a retransmission, which reuses the identifier of a transaction NCM has already answered and draws `transactionIdInUse`.

### Request rate limiting

The NCM CMP listener applies a per-host request limit that is independent of CMP semantics. Once a client exceeds it, the listener answers HTTP 503 with an HTML body and no CMP message, rejecting the request before it parses the header or reaches the CA engine. The limit counts every CMP request from the source address, including `certConf` and `pollReq`, so a busy controller or a tight retry loop can trip it. cmp-issuer reports these as transport errors and retries with backoff.

## EJBCA Community Edition 9.3.7

| Item | Value |
| --- | --- |
| Product | [EJBCA Community Edition 9.3.7](https://www.ejbca.org) |
| Mode | CMP alias in **client mode** and in **RA mode** |
| Protection tested | PasswordBasedMac, certificate signature |
| Transports tested | HTTP and HTTPS |
| Authentication modules | HMAC and EndEntityCertificate |

### Continuously verified

Enrollment against EJBCA runs in CI after changes land on `dev` or `main`, against a server started in the test cluster. Pull requests omit this expensive job. Each run issues real certificates through cert-manager `Certificate` resources over three combinations: a shared secret over HTTP, the same over HTTPS and a certificate signature over HTTP. The endpoint certificate is verified against a pinned authority that did not sign the CMP responses, so a run also confirms that the CMP trust and the transport trust are decided separately.

### RA mode

In RA mode EJBCA registers the end entity from the request itself, using `ra.namegenerationscheme` `DN` with `ra.namegenerationparameters` `CN` to take the name from the request subject. A repeated enrollment of the same subject is answered with a new certificate rather than refused, so RA mode avoids the client mode constraint below.

### Response protection

An EJBCA CMP alias decides how it protects its answers with `responseprotection`. Under `signature`, which is the setting the tested aliases use, the issuing CA signs every response including the answer to a request protected with a shared secret. cmp-issuer requires a `PasswordBasedMac` request to be answered with MAC-based protection unless the issuer sets `spec.protocol.macResponseProtection` to `AllowSignature`, so a shared secret issuer pointed at such an alias needs that value. The signer must still chain to `spec.cmpTrust.caSecretRef` and its sender must still name `spec.protocol.recipient`. An alias set to `responseprotection` `pbe` answers a shared secret request with MAC-based protection and works under the `Strict` default.

### Client mode constraints

**End entity must exist and returns to a used state.** Client mode treats the enrollment code as one-time. After issuance the end entity moves to `GENERATED` and refuses another request until an administrator sets it back to `NEW` or the profile allows multiple requests.

**Certificate authentication enrolls only the authenticating identity.** With `EndEntityCertificate` in client mode EJBCA requires the requested subject DN to match the registered end entity. Signature protection therefore issues for the bootstrap identity.

**Signature credential shape.** EJBCA resolves the certificate from its database. The Secret needs only `tls.crt` and `tls.key`; `chainKey` may be omitted.

### P10CR certReqId

EJBCA returns `0`. Pinning `-1` fails with a permanent error and issues no certificate.

### Retransmitted enrollment

EJBCA answers a repeat of an enrollment it already accepted with a protected error carrying failInfo `badRequest` and the status text `Got request with status GENERATED (40)`, and issues no second certificate. It refuses on the end entity state above rather than on the transaction identifier, so like NCM it does not return the certificate from the original transaction.

## OpenSSL CMP mock

CI runs delayed enrollment, delayed confirmation and pinned transaction flows against the CMP mock built into OpenSSL 3.6. This is an independent oracle with no shared code with cmp-issuer or go-pkicmp. The pinned transaction coverage confirms that the identifier recorded before sending is the identifier OpenSSL saw on the wire.

The mock keeps one transaction per TCP connection. The test reaches it through a connection-pooling proxy because RFC 6712 does not require connection affinity on real servers. The mock returns a fixed certificate rather than signing the request, so it cannot show how a server treats a repeat; that behavior is recorded above from NCM and EJBCA.

## What is not claimed

* Compatibility with arbitrary CMP servers or profiles
* IR, KUR, revocation or CMPv3

See [Support matrix](../support-matrix.md).
