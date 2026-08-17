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
| CMPv2 KUR (true key update) | Planned | Distinct from cert-manager renewal or P10CR re-enrollment |
| cert-manager Certificate renewal | Unsupported as KUR | May succeed only when the server treats repeat P10CR as allowed |
| Explicit `certConf` confirmation | Implemented, Interoperability tested | Default |
| Server-granted implicit confirmation | Implemented | Set `protocol.confirmation: Implicit` |
| Asynchronous `waiting` / `pollReq` / `pollRep` | Implemented, Interoperability tested | Bounded by `spec.transaction` |
| Delayed confirmation (`certConf` answered with `waiting`) | Implemented, Interoperability tested | Polled from `CMPTransaction`, resumable across a restart |
| CMPv3 | Planned | |
| Revocation (RR, CRL, OCSP over CMP) | Planned | |

## Message protection

| Capability | Status | Notes |
| --- | --- | --- |
| PasswordBasedMac (SHA-256 OWF, HMAC-SHA-256) | Implemented, Interoperability tested | RFC 4210 style |
| PBMAC1 | Planned | |
| Certificate signature protection | Implemented, Interoperability tested | Bootstrap credential in a Secret |
| Unprotected CMP | Unsupported | Every request and response must be protected |

## Transport

| Capability | Status | Notes |
| --- | --- | --- |
| HTTP CMP endpoint | Implemented, Interoperability tested | No transport confidentiality |
| HTTPS with custom trust anchors | Implemented | TLS trust is separate from CMP trust |
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
| `p10crResponseCertReqId` pin | Implemented | Accept `-1` or `0` by default |
| Endpoint reachability in issuer readiness | Planned | Readiness reflects configuration, not whether the server answers |
| Requested validity period from `Certificate.spec.duration` | Planned | Needs CRMF, since a PKCS #10 request carries no validity |
| Chain placement options for the issued Secret | Planned | Choose whether `tls.crt` carries the chain and what `ca.crt` holds |

## Observability

| Capability | Status | Notes |
| --- | --- | --- |
| Controller runtime and Go metrics | Implemented | Standard controller-runtime endpoint, protected by authn and authz |
| Structured issuance logging with certificate detail | Implemented, Interoperability tested | One line per enrollment outcome with subject, serial, validity, SANs, key type and size, signature algorithm, issuing CA and duration. The logged transaction identifier matches the one the CMP server records |
| CMP message logging | Implemented, Interoperability tested | Body type and size of each message sent and received, behind `logging.level: debug` |
| Enrollment, poll and confirmation metrics | Planned | Counts and durations per issuer and outcome |
| Conformance testing against a third-party CMP profile suite | Planned | Bundled with the CRMF and PBMAC1 work, which is where an external RFC 9483 harness adds coverage the tested servers cannot |

## Tested CMP servers

| Server | Protection modes tested | Status |
| --- | --- | --- |
| Nokia NCM 26.7 / Insta Certifier 7.20 | PasswordBasedMac, Signature | Interoperability tested |
| EJBCA Community Edition 9.3.7 (client mode alias) | PasswordBasedMac, Signature | Interoperability tested |
| OpenSSL CMP mock (`openssl cmp`) | PasswordBasedMac | Interoperability tested in CI |

See [Tested PKIs](interoperability/tested-pkis.md) for server-specific configuration notes.
