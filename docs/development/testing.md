# Testing

cmp-issuer validation spans unit tests, envtest, OpenSSL interoperability, Kind e2e and manual verification against real CMP servers.

## Unit and envtest

```bash
make test
```

Coverage includes:

* Protocol adapter encoding and verification
* Signer and controller reconciliation
* Deferred enrollment over real CMP messages with transaction state on a real API server
* Delayed confirmation and nonce echo rules

## OpenSSL CMP interoperability

CI runs delayed transaction and delayed confirmation flows against the OpenSSL 3.6 CMP mock. The workflow fails if the test is silently skipped when OpenSSL is available.

Locally set `OPENSSL_BIN` to select a non-default OpenSSL binary. The test skips when OpenSSL is missing.

The mock uses one transaction per TCP connection. A pooling proxy forwards tests without changing CMP bytes.

## Kind e2e suite

```bash
make test-e2e
```

Requires Colima or Docker for Kind. The suite:

* Creates an isolated Kind cluster
* Installs cert-manager and cmp-issuer
* Verifies issuer readiness and Secret naming on failure
* Validates accepted `p10crResponseCertReqId` values
* Confirms denied requests send no CMP traffic and store no certificate
* Confirms connection failures store no partial material
* Confirms crafted private-key annotations do not expose Secrets
* Confirms Secret access requires the documented RoleBinding

Runtime is about one minute after the cluster is ready. **Do not run this suite against a production cluster.**

## Interoperability against real CMP servers

Enrollment against NCM and EJBCA is verified manually against dedicated CMP servers, because running a certificate authority inside the test cluster costs far more per run than the rest of the suite. Outcomes are summarized in [Tested PKIs](../interoperability/tested-pkis.md).

## Lint and supply chain

```bash
make lint
make govulncheck
make gitleaks
make sbom
make scan-image IMG=<image>
```

CI runs these on push and on a weekly schedule.

## Related pages

* [Development](development.md)
* [Release process](release-process.md)
