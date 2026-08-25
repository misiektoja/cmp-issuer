# Tested PKIs

cmp-issuer has completed protected P10CR enrollment and renewal tests against the servers below. KUR coverage is stated separately because support depends on the server profile and alias mode. Compatibility for any other server depends on its CMP profile, enabled operations, algorithms, endpoint structure and authentication policy.

## Contents

* [Nokia NCM 26.7 / Insta Certifier 7.20](#nokia-ncm-267-insta-certifier-720)
* [EJBCA Community Edition 9.3.7](#ejbca-community-edition-937)
* [OpenSSL CMP mock](#openssl-cmp-mock)
* [What is not claimed](#what-is-not-claimed)

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

### KUR renewal

The same lab profile accepted a P10CR-issued certificate as the authentication credential for later KUR on the same endpoint. Both cert-manager rotation policies completed with explicit confirmation. `Always` produced a new serial and public key while `Never` produced a new serial with the exact existing public key. NCM recorded signature-protected `keyUpReq`, `keyUpResp`, `certConfirm` and final confirmation messages.

This verifies both new-key and same-key KUR against the tested profile. Another NCM profile can still disable key update or apply different certificate policy.

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

Enrollment against EJBCA runs in CI after changes land on `dev` or `main`, against a server started in the test cluster. Pull requests omit this expensive job. Each run issues real certificates through cert-manager `Certificate` resources over shared-secret HTTP and HTTPS plus certificate-signature HTTP. It also renews dedicated client-mode identities through KUR with `rotationPolicy` `Always` and `Never`. The endpoint certificate is verified against a pinned authority that did not sign the CMP responses, so a run also confirms that the CMP trust and transport trust are decided separately.

### RA mode

In RA mode EJBCA registers the end entity from the request itself, using `ra.namegenerationscheme` `DN` with `ra.namegenerationparameters` `CN` to take the name from the request subject. A repeated enrollment of the same subject is answered with a new certificate rather than refused, so RA mode avoids the client mode constraint below.

### Response protection

An EJBCA CMP alias decides how it protects its answers with `responseprotection`. Its own default is `signature`, which the tested aliases keep, so the issuing CA signs every response including the answer to a request protected with a shared secret. This works with no extra configuration, because `spec.protocol.macResponseProtection` defaults to `AllowSignature`. The signer still has to chain to `spec.cmpTrust.caSecretRef` and its sender still has to name `spec.protocol.recipient`. Setting `macResponseProtection` to `Strict` against such an alias fails every enrollment after the certificate has already been issued, so pair it with `responseprotection` `pbe`, which answers a shared secret request with MAC-based protection.

### Client mode constraints

**End entity must exist and returns to a used state.** Client mode treats the enrollment code as one-time. After issuance the end entity moves to `GENERATED` and refuses another request until an administrator sets it back to `NEW` or the profile allows multiple requests.

**Certificate authentication enrolls only the authenticating identity.** With `EndEntityCertificate` in client mode EJBCA requires the requested subject DN to match the registered end entity. Signature protection therefore issues for the bootstrap identity.

**Signature credential shape.** EJBCA resolves the certificate from its database. The Secret needs only `tls.crt` and `tls.key`; `chainKey` may be omitted.

### KUR in client mode

Initial P10CR uses a client-mode HMAC alias. KUR uses a separate `EndEntityCertificate` alias with Automatic Key Update enabled. Configure the first URL as `endpoint.url`, the key-update alias as `endpoint.renewalUrl` and select `protocol.renewal: KUR`.

The initial P10CR-issued certificate successfully authenticates later KUR. EJBCA issues a new serial for both a new requested key and the existing key when `allowupdatewithsamekey` is enabled. No administrative reset is used between revisions.

EJBCA 9.3.7 includes the issuing CA in KUP `caPubs` by default. The default `Interoperable` validation profile accepts it only as an untrusted chain candidate and still requires the issued chain to terminate at configured CMP trust. The continuously verified fixture exercises this default. A second KUR alias disables `response.capubsissuingca` and exercises `validationProfile: RFC9483` during renewal.

### P10CR certReqId

EJBCA returns `0`. Pinning `-1` fails with a permanent error and issues no certificate.

Because `validationProfile: RFC9483` pins P10CR responses to `-1`, the EJBCA fixture performs initial enrollment with `Interoperable` then enables the strict profile before KUR. This validates the strict key-update response rules without claiming that EJBCA's P10CR response follows RFC 9483.

### Retransmitted enrollment

EJBCA answers a repeat of an enrollment it already accepted with a protected error carrying failInfo `badRequest` and the status text `Got request with status GENERATED (40)`, and issues no second certificate. It refuses on the end entity state above rather than on the transaction identifier, so like NCM it does not return the certificate from the original transaction.

## OpenSSL CMP mock

CI runs delayed enrollment, delayed confirmation, pinned transaction and KUR flows against the CMP mock built into OpenSSL 3.6. This is an independent oracle with no shared code with cmp-issuer or its CMP encoding library. KUR is exercised with new-key and same-key CRMF proof of possession. The pinned transaction coverage confirms that the identifier recorded before sending is the identifier OpenSSL saw on the wire.

The mock keeps one transaction per TCP connection. The test reaches it through a connection-pooling proxy because RFC 6712 does not require connection affinity on real servers. The mock returns a fixed certificate rather than signing the request, so it cannot show how a server treats a repeat; that behavior is recorded above from NCM and EJBCA.

## What is not claimed

* Compatibility with arbitrary CMP servers or profiles
* IR, revocation or CMPv3

See [Support matrix](../support-matrix.md).
