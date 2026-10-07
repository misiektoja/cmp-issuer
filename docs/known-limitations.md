# Known limitations

Behavior to plan around in the current release. Each item states what is not covered and the failure it can produce.

## Transaction durability

cmp-issuer records the operation, transaction identifier, issuer and Secret configuration identity plus the issued chain in `CMPTransaction`, so an asynchronous enrollment survives a controller restart and an interrupted attempt resumes under its original transaction identifier rather than starting a new one. The gaps below remain.

### A lost enrollment response cannot be recovered

If the controller stops after sending an enrollment and the response never arrives, retrying under the recorded transaction identifier reliably prevents a second certificate but does not retrieve the first one. Neither tested server answers the repeat from its existing transaction: Nokia NCM 26.7 refuses it with `transactionIdInUse` and EJBCA CE 9.3.7 refuses it with `badRequest`. The `CertificateRequest` fails and cert-manager enrolls again under a new transaction identifier, which succeeds. The certificate the server issued for the lost response is orphaned and counts against any issuance quota or audit trail the certificate authority keeps.

### Coarse progress reporting

`CMPTransaction.status.phase` reports `Enrolling`, `Polling`, `Confirming` or `Issued`, so `kubectl get cmptransactions` shows less detail than the underlying message flow.

### Completed transactions are retained

A transaction that obtained a certificate keeps its record, including the issued chain, so that a restart before cert-manager stores the certificate does not enroll a second one. The record is removed only when the owning `CertificateRequest` is garbage collected, so `kubectl get cmptransactions` lists completed transactions next to in-flight ones.

## Protocol and product scope

| Limitation | Status |
| --- | --- |
| IR and CRMF | Planned |
| `spec.protocol.certProfile` | Reserved until its CMP encoding is implemented. A non-empty value makes the issuer NotReady |
| KUR with a changed subject or SAN | Unsupported by design. Use P10CR where the server permits re-enrollment or wait for planned CR support |
| KUR after the old certificate expires | Unsupported by RFC profile requirements. Renew while it is still valid |
| PBMAC1 | Planned |
| mTLS to the CMP endpoint | Planned. Setting the reserved `spec.transport.tls.clientCertificateSecretRef` makes the issuer NotReady |
| CMPv3 beyond ML-DSA certificate confirmation | Planned |
| Composite ML-DSA | Unsupported. cert-manager rejects composite CSRs and Go cannot validate composite certificate chains |
| Revocation over CMP | Planned |
| Kubernetes CSR signing | Unsupported by design |
| Broad CMP compatibility | Not claimed |

See [Support matrix](support-matrix.md).

## ML-DSA

cmp-issuer issues and renews ML-DSA certificates. cert-manager decides whether an ML-DSA request reaches it.

* cert-manager v1.21 is built with Go 1.26, so its webhook rejects a `CertificateRequest` that carries an ML-DSA CSR. cert-manager built with Go 1.27 accepts one, whether it is a release or your own build.
* Building cert-manager with Go 1.27 does not add ML-DSA to `Certificate` resources. `Certificate.spec.privateKey.algorithm` offers only `RSA`, `ECDSA` and `Ed25519`. cert-manager also compares keys only of those types, so it cannot match an ML-DSA key in a Secret to its certificate. A `Certificate` therefore cannot generate, store or renew an ML-DSA key. This needs changes in cert-manager itself, tracked in [cert-manager#8929](https://github.com/cert-manager/cert-manager/issues/8929).
* Until then, an ML-DSA certificate needs a directly created `CertificateRequest` with an ML-DSA CSR, which cmp-issuer enrolls with P10CR. cert-manager does not renew it, so renew by creating a new `CertificateRequest`.
* KUR reads ML-DSA keys from `tls.key` in the seed-only PKCS #8 form the Go standard library writes. cert-manager has not decided how it will store ML-DSA keys, so KUR depends on that choice.
* Go reads only seed-only ML-DSA private keys. OpenSSL writes the seed and the expanded key by default, so convert an ML-DSA CMP signature credential before storing it: `openssl pkey -in key.pem -provparam ml-dsa.output_formats=seed-only -out seed-key.pem`.
* `kubectl create secret tls` with an ML-DSA key prints `Warning: tls: failed to parse private key`. The Secret is still created and cmp-issuer reads it.
* The `certConf` for a certificate signed with ML-DSA carries a SHA-512 `certHash` and names SHA-512 in `hashAlg`. The OpenSSL CMP mock server ignores `hashAlg` and checks the hash with SHA-256, so explicit confirmation fails against it. Use implicit confirmation with that server.

## Dependencies

The CMP library is pre-v1. [ADR 0001](adr/0001-cmp-library.md) describes the dependency boundary and validation requirements.

## API stability

`certmanager.misiektoja.github.io/v1alpha1` may change before a stable version.

## Related pages

* [Transaction recovery](guide/transaction-recovery.md)
* [Threat model](security/threat-model.md)
