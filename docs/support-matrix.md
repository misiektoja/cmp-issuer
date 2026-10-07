# Support matrix

cmp-issuer implements a narrow CMPv2 profile for cert-manager external issuance. Compatibility depends on each server's CMP profile, enabled operations, algorithms, endpoint structure and authentication policy. Do not assume broad CMP compatibility.

## Legend

| Status | Meaning |
| --- | --- |
| **Implemented** | Code exists and unit or envtest coverage exercises it |
| **Interoperability tested** | Verified against at least one independent CMP server or oracle |
| **Experimental** | Implemented but the API or behavior may still change |
| **Planned** | Recorded on the roadmap, not implemented |
| **Unsupported** | Out of scope for the current release |

## Operations and protocol

| Capability | Status | Notes |
| --- | --- | --- |
| CMPv2 P10CR initial enrollment | Implemented, Interoperability tested | PKCS #10 in P10CR, CP response |
| CMPv2 IR (CRMF) | Planned | Requires workload private-key access |
| CMPv2 KUR (true key update) | Implemented, Interoperability tested | Certificate-authenticated CRMF with proof of possession. Verified with new-key and same-key renewal against Nokia NCM 26.7, EJBCA 9.3.7 and OpenSSL 3.6.3 |
| cert-manager Certificate renewal | Implemented as selectable P10CR or KUR | P10CR is the compatibility default. KUR is opt-in through `protocol.renewal` |
| Explicit `certConf` confirmation | Implemented, Interoperability tested | Default |
| Rejecting `certConf` for a refused certificate | Implemented | Sent when the issued certificate does not certify the CSR key, fails chain validation or carries modifications refused by `policy.grantedModifications: Reject` |
| Server-granted implicit confirmation | Implemented | Set `protocol.confirmation: Implicit` |
| Asynchronous `waiting` / `pollReq` / `pollRep` | Implemented, Interoperability tested | Bounded by `spec.transaction` |
| Delayed confirmation (`certConf` answered with `waiting`) | Implemented, Interoperability tested | Polled from `CMPTransaction`, resumable across a restart |
| CMPv3 `certConf` with `hashAlg` | Implemented | Used to confirm a certificate signed with ML-DSA. A CMPv2 or CMPv3 answer is accepted |
| Other CMPv3 features | Planned | |
| Revocation (RR, CRL, OCSP over CMP) | Planned | |

## Key algorithms

| Capability | Status | Notes |
| --- | --- | --- |
| RSA, ECDSA and Ed25519 keys | Implemented, Interoperability tested | Workload keys and CMP signature credentials |
| ML-DSA-44, ML-DSA-65 and ML-DSA-87 workload keys | Implemented, Interoperability tested | P10CR and KUR. cert-manager v1.21 cannot submit ML-DSA requests, see [Known limitations](known-limitations.md#ml-dsa) |
| ML-DSA CMP signature credential | Implemented | PKCS #8 seed-only private key |
| ML-DSA CA and ML-DSA-signed CMP responses | Implemented, Interoperability tested | |
| Composite ML-DSA | Unsupported | cert-manager rejects composite CSRs and Go cannot validate composite certificate chains |

## Message protection

| Capability | Status | Notes |
| --- | --- | --- |
| PasswordBasedMac (SHA-256, SHA-384 or SHA-512) | Implemented, Interoperability tested | HMAC digest cannot be longer than OWF output. SHA-256 defaults |
| PBMAC1 | Planned | |
| Certificate signature protection | Implemented, Interoperability tested | Bootstrap credential in a Secret |
| Trust anchor as response signer | Implemented, Interoperability tested | Both validation profiles accept an anchor from `cmpTrust` when its certificate is absent from response `extraCerts` |
| Configured response signer certificates | Implemented, Interoperability tested | Optional `cmpTrust.signerCertificatesSecretRef` supplies signers omitted from `extraCerts` and issued-chain intermediates without adding trust anchors |
| Unprotected CMP | Unsupported | Every request and response must be protected |

## Transport

| Capability | Status | Notes |
| --- | --- | --- |
| HTTP CMP endpoint | Implemented, Interoperability tested | No transport confidentiality |
| HTTPS with custom trust anchors | Implemented, Interoperability tested | TLS trust is separate from CMP trust, and the two anchors are different authorities in the tested setup |
| HTTPS with system trust | Implemented | Omit `transport.tls.caSecretRef` |
| mTLS client authentication | Planned | `clientCertificateSecretRef` is reserved |
| Backup CMP endpoint with failover | Planned | A second endpoint used when the primary is unreachable |
| Explicit outbound proxy settings | Planned | Standard proxy environment variables are already honored |
| HTTP redirects | Unsupported | Disabled; redirect responses fail closed |

## Issuer API

| Capability | Status | Notes |
| --- | --- | --- |
| `CMPIssuer` (namespaced) | Experimental | API group `certmanager.misiektoja.github.io/v1alpha1` |
| `CMPClusterIssuer` (cluster) | Experimental | Credentials read from cluster resource namespace |
| `CMPTransaction` persistence | Implemented, Interoperability tested | Survives controller restart, returns the recorded chain and retries under the pinned transaction identifier so a repeat cannot issue a second certificate |
| Kubernetes CSR signing | Unsupported | CSR controller deliberately disabled |
| `p10crResponseCertReqId` pin | Implemented | Interoperable profile accepts `-1` or `0`. RFC 9483 profile requires `-1` |
| `protocol.renewal` | Implemented | `P10CR` by default or `KUR` for later cert-manager revisions |
| `protocol.validationProfile` | Implemented | `Interoperable` by default or bundled RFC 9483 receiver checks for implemented P10CR and KUR flows |
| `protocol.kurResponseCaPubs` | Implemented | Accept untrusted KUP chain candidates by default or require the field absent |
| `endpoint.renewalUrl` | Implemented | Optional KUR endpoint for servers with separate initial and key-update aliases |
| `macResponseProtection` | Implemented, Interoperability tested | Interoperable profile uses `AllowSignature`, so a signed answer to a `PasswordBasedMac` request is accepted when it chains to the CMP trust anchor and names the recipient. RFC 9483 uses `Strict` |
| Endpoint reachability in issuer readiness | Planned | Readiness reflects configuration, not whether the server answers |
| Requested validity period from `Certificate.spec.duration` | Planned | Needs CRMF, since a PKCS #10 request carries no validity |
| Chain placement options for the issued Secret | Planned | Choose whether `tls.crt` carries the chain and what `ca.crt` holds |

## Observability

| Capability | Status | Notes |
| --- | --- | --- |
| Controller runtime and Go metrics | Implemented | Standard controller-runtime endpoint, protected by authn and authz. The serving certificate can be issued by cert-manager so a scraper verifies the endpoint rather than skipping verification |
| Structured issuance logging with certificate detail | Implemented, Interoperability tested | One line per enrollment outcome with subject, serial, validity, SANs, key type and size, signature algorithm, issuing CA and duration. The logged transaction identifier matches the one the CMP server records |
| CMP message logging | Implemented, Interoperability tested | Body type and size of each message sent and received, behind `logging.level: debug` |
| Enrollment, poll and confirmation metrics | Implemented, Interoperability tested | Attempts, durations, classified failures, poll waits and confirmation types, labelled per issuer and split between enrollment and renewal. See [metrics](operations/metrics.md) |
| Conformance testing against a third-party CMP profile suite | Planned | Bundled with the CRMF and PBMAC1 work, which is where an external RFC 9483 harness adds coverage the tested servers cannot |

## Tested CMP servers

| Server | Protection modes tested | Status |
| --- | --- | --- |
| Nokia NCM 26.7 / Insta Certifier 7.20 | PasswordBasedMac, Signature | Interoperability tested |
| EJBCA Community Edition 9.3.7 (client mode and RA mode aliases) | PasswordBasedMac, Signature | Interoperability tested in CI |
| OpenSSL CMP mock (`openssl cmp`) | PasswordBasedMac, Signature | Interoperability tested in CI |

See [Tested PKIs](interoperability/tested-pkis.md) for server-specific configuration notes.
