# cmp-issuer

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP) servers.

The first implementation target is CMPv2 initial enrollment with a PKCS #10 request carried in P10CR and a CP response. CMP message protection is mandatory. HTTP and HTTPS are both supported transports. HTTP does not provide transport confidentiality.

This repository is under active initial development. The protocol adapter and controller foundation are not production ready. PasswordBasedMac and certificate-signature P10CR have both completed protected cert-manager `Certificate` enrollments against two independent CMP servers: NCM 26.7 with Insta Certifier 7.20 build 43974, and EJBCA Community Edition 9.3.7.

## API foundation

The API group is `certmanager.misiektoja.github.io` with `CMPIssuer` and `CMPClusterIssuer` kinds at `v1alpha1`. A namespaced issuer reads credential Secrets only from its namespace. A cluster issuer reads them only from the controller's configured cluster resource namespace.

PasswordBasedMac with SHA-256 and HMAC-SHA-256 plus certificate-based signature protection are implemented behind a project-owned protocol interface. The current milestone supports CMPv2 P10CR and CP with explicit or server-granted implicit confirmation, and asynchronous transactions in which the server answers `waiting` and the issuer polls until the certificate is issued.

`initialEnrollment` accepts only `P10CR`. IR needs CRMF proof of possession over the workload private key, which the issuer deliberately never reads, so it is not offered as a configurable value.

## Asynchronous transactions

A CA that queues requests or requires manual approval answers the enrollment with `waiting` instead of a certificate. The issuer then sends `pollReq` messages until the CA returns the certificate, and confirms it normally.

Because such a transaction can outlive the controller process, its state is durable. Before the first message is sent the controller records a `CMPTransaction` resource next to the `CertificateRequest`, holding the CMP transaction identifier, the nonce the next message must echo, the polled `certReqId` and the response signer already validated for the transaction. A restart therefore resumes the existing transaction rather than starting a second enrollment for the same request. The resource is owned by its `CertificateRequest`, so it is removed with it, and the controller deletes it as soon as the transaction succeeds or fails permanently.

Inspect an enrollment that has not completed:

```bash
kubectl get cmptransactions -A
```

The `transaction` block bounds this behavior:

```yaml
spec:
  transaction:
    maximumDuration: 10m
    minimumPollInterval: 1s
    maximumPollInterval: 5m
    maximumPolls: 60
```

The issuer waits for the interval the server requests in `pollRep`, clamped into `minimumPollInterval` and `maximumPollInterval`. A server that asks for no interval gets `minimumPollInterval`. The transaction fails once it exceeds `maximumDuration` or sends `maximumPolls` poll messages, and the recorded state is removed.

One case is deliberately not recoverable. If the controller stops between recording a transaction and receiving the response to its enrollment request, the outcome of that request is unknown. The retry re-sends the enrollment under the same recorded transaction identifier, which is how a CMP server recognises a repeated request rather than a new enrollment, so servers that enforce transaction identifiers will not issue twice.

A server may also delay the confirmation rather than the certificate, answering `certConf` with `waiting` instead of `pkiConf`. RFC 9483 section 4.4 applies delayed delivery to every operation, so the issuer polls for the confirmation as well. That wait is not governed by the settings above and is not recorded in a `CMPTransaction`, because the certificate has already been issued at that point and only the acknowledgement is outstanding. The issuer polls inline for up to one minute, waiting between one and ten seconds as the server requests, and fails the request if the confirmation does not arrive. Configure `implicitConfirm` to skip this exchange entirely on servers that grant it.

## Security boundaries

For P10CR the controller forwards the signed PKCS #10 CSR supplied by cert-manager. It does not read the workload private key or cert-manager's staging private-key Secret. TLS trust and CMP response-protection trust are configured separately.

See [the threat model](docs/security/threat-model.md) and [provenance record](docs/provenance.md) before evaluating the project.

Secret access is intentionally not cluster-wide. The base installation grants access only in `cmp-issuer-system` for `CMPClusterIssuer` credentials. Each namespace that uses `CMPIssuer` requires an administrator-created RoleBinding as described in [credential Secret access](docs/operations/secret-access.md).

## P10CR response compatibility

RFC 9810 section 5.3.4 and RFC 9483 section 4.1.4 both require the `certReqId` of a P10CR `cp` response to be `-1`, because a PKCS #10 request carries no request identifier to match. Both servers tested so far, NCM 26.7 and EJBCA Community Edition 9.3.7, return `0` instead.

By default the issuer therefore accepts either `-1` or `0`, echoes the value it received in `certConf` and rejects any other value. No other part of the transaction depends on this identifier. A P10CR `cp` must still contain exactly one `CertResponse`, the response must be protected and trusted, the issued public key must match the CSR and the chain must validate against the configured CMP trust.

Pin the identifier when a server's behavior is known and any other value should be treated as a protocol failure:

```yaml
spec:
  protocol:
    p10crResponseCertReqId: -1
```

A pinned issuer requires that exact value in `cp` and echoes it in `certConf`.

## NCM interoperability notes

PasswordBasedMac and certificate-signature protected P10CR both complete against NCM 26.7 with Insta Certifier 7.20 build 43974, including `certConf` and a protected `pkiConf`. Two behaviors are recorded here because they are easy to misdiagnose.

**NCM omits signer identification from `pkiConf`.** Its `cp` is signature protected and carries the signer certificate in `extraCerts`. The final `pkiConf` carries no `extraCerts` and no `senderKID`, so a client that rediscovers the signer for every message independently cannot verify it. cmp-issuer retains the signer certificate that it already validated against the configured CMP trust anchors when it accepted `cp`, and verifies the linked `pkiConf` against that certificate. Protection stays mandatory: a `pkiConf` that fails verification against the retained signer is still rejected and no certificate is returned.

**A P10CR must carry its own signer certificate in `extraCerts`.** NCM resolves the signing certificate from `extraCerts` using `senderKID`. cmp-issuer sends the protection certificate followed by its configured chain, and NCM accepts it. The vendor `ssh-cmpclient P10CR` sends only the issuing chain and omits the end-entity certificate that its own `senderKID` names, so NCM answers `CMP header protection check failed`. That rejection is a property of the vendor client's P10CR message rather than of the server profile or the credentials, which the same client uses successfully for `INITIALIZE`.

An earlier revision of this file reported that cmp-issuer could not verify NCM's protected error responses. That claim is retracted. NCM's protected error message verifies against the configured CMP trust anchor. The confirmation signer handling described above was the actual defect.

## EJBCA interoperability notes

PasswordBasedMac and certificate-signature protected P10CR both complete against EJBCA Community Edition 9.3.7 using a CMP alias in client mode. EJBCA client mode enforces its own enrollment rules, and three of them determine how an issuer must be configured.

**The end entity must exist before enrollment and returns to a used state afterwards.** Client mode treats the enrollment code as a one-time credential. After a certificate is issued the end entity moves to `GENERATED` and refuses another request until an administrator sets it back to `NEW`, or until the end entity profile allows more than one request. This applies to both protection types, so a repeatedly renewing workload needs either a raised request count or an RA-mode alias.

**Certificate authentication enrolls only the identity that owns the authenticating certificate.** With the `EndEntityCertificate` authentication module in client mode, EJBCA resolves the certificate sent in `extraCerts`, confirms it belongs to the requesting end entity and requires the requested subject DN to match the registered one. A `CMPIssuer` using signature protection therefore issues for the identity of its own credential rather than for arbitrary workloads.

**The signature credential needs only the end-entity certificate and its key.** EJBCA looks the certificate up in its own database, so `chainKey` may be omitted:

```yaml
spec:
  protection:
    type: Signature
    signature:
      secretRef:
        name: ejbca-signature-credentials
      certificateKey: tls.crt
      privateKeyKey: tls.key
```

Like NCM, EJBCA answers P10CR with `certReqId` `0`. Pinning `-1` against it fails the request permanently with `P10CR CP certReqId must be -1 but response contained 0` and issues no certificate.

## Automated verification

Unit and envtest coverage runs with `make test`. It includes a deferred enrollment driven against a CMP server that answers `waiting`, polls and then issues, so the asynchronous path is exercised over real CMP messages rather than mocked, and it records transaction state through a real API server. Delayed confirmation is covered as well, including a server that echoes the nonce of the delayed request rather than of the last poll.

The polling flow has also been verified by hand against the CMP mock server built into OpenSSL 3.6 (`openssl cmp -port`), an implementation unrelated to the one used in the tests, driving a full `P10CR` to `waiting` to `pollReq` to `certConf` to `waiting` to `pollReq` to `pkiConf` transaction. Note that this mock server keeps one transaction per connection, so it needs all messages of a transaction on a single HTTP connection, which RFC 6712 does not require of a CMP server.

Controller behavior is verified against a real cluster by an end-to-end suite that needs no CMP server:

```bash
make test-e2e
```

The suite creates a Kind cluster, installs cert-manager and the controller, and then proves that:

* A `CMPIssuer` becomes ready only when its credential and trust Secrets are readable in its own namespace, and reports the offending Secret by name when either is missing.
* The API accepts `p10crResponseCertReqId` values of `-1` and `0` and rejects any other value.
* A denied `CertificateRequest` produces no CMP message and stores no certificate.
* A request whose endpoint refuses connections fails visibly and stores no partial material.
* A crafted `cert-manager.io/private-key-secret-name` annotation leaves the Secret it names unmodified.
* The controller can read Secrets only in namespaces that carry the documented RoleBinding.

The specs complete in about a minute after the cluster is up. Interoperability with real CMP servers is verified separately in a lab against NCM and EJBCA, and recorded in the interoperability notes above, because running a certification authority in the test cluster costs more than ten minutes per run.

## Installation

The installer manifest carries the CRDs, RBAC and the controller Deployment:

```bash
make build-installer IMG=<registry>/cmp-issuer:<tag>
kubectl apply -f dist/install.yaml
```

A Helm chart is available in `charts/chart` for installations that need values-driven configuration:

```bash
helm install cmp-issuer ./charts/chart --namespace cmp-issuer-system --create-namespace
```

Both install the same resources. Neither grants the controller Secret access in workload namespaces, so add the RoleBinding from [credential Secret access](docs/operations/secret-access.md) for every namespace that uses a `CMPIssuer`.

## Supply chain

| Command | Purpose |
| --- | --- |
| `make govulncheck` | Report known vulnerabilities that reach the module or its dependencies |
| `make gitleaks` | Scan the working tree and the commit history for leaked credentials |
| `make sbom` | Write a CycloneDX bill of materials to `dist/cmp-issuer.cdx.json` |
| `make scan-image IMG=<image>` | Scan a built manager image for fixed operating system and Go vulnerabilities |
| `make helm-lint` | Lint and render the Helm chart |
| `make docs-build` | Build the documentation site with strict validation |

Every check runs in CI on each push and once a week. Releases are described in [the provenance record](docs/provenance.md).

## License

Original cmp-issuer code is licensed under GPL-3.0-only. Dependencies retain their own licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
