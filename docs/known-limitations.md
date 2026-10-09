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

cmp-issuer supports ML-DSA-44, ML-DSA-65 and ML-DSA-87. Enrollment requires a CMP server that accepts the chosen algorithm and a cert-manager build that admits ML-DSA CSRs.

* cert-manager v1.21 is built with Go 1.26 and rejects ML-DSA CSRs. Go 1.27 provides the required cryptography, but admission also depends on the cert-manager build and its feature gates. The upstream [ML-DSA design proposal](https://github.com/cert-manager/cert-manager/pull/9436) introduces an alpha `MLDSAPrivateKeys` gate for the controller and webhook. Follow the instructions for your build.
* If the build admits ML-DSA CSRs but cannot manage ML-DSA keys, submit a direct `CertificateRequest` for P10CR enrollment. Renew by submitting another request. Automatic issuance and renewal through `Certificate` resources require cert-manager support for ML-DSA key generation, storage and matching. A Go rebuild alone does not provide that support.
* KUR requires cert-manager to supply the current and requested ML-DSA keys in seed-only PKCS #8 form. cmp-issuer reads the keys and CSR independently of the algorithm name used by the cert-manager API.
* Go reads only seed-only ML-DSA private keys. OpenSSL writes the seed and the expanded key by default, so convert an ML-DSA CMP signature credential before storing it: `openssl pkey -in key.pem -provparam ml-dsa.output_formats=seed-only -out seed-key.pem`.
* A `kubectl` build without ML-DSA support may print `Warning: tls: failed to parse private key` during `kubectl create secret tls`. Check whether the Secret was created.
* The `certConf` for a certificate signed with ML-DSA carries a SHA-512 `certHash` and names SHA-512 in `hashAlg`. The OpenSSL CMP mock server ignores `hashAlg` and checks the hash with SHA-256, so explicit confirmation fails against it. Use implicit confirmation with that server.

### Key usages

Set `usages: [digital signature]` for an ML-DSA request and configure the CA profile accordingly. Add extended usages such as `server auth` when needed. Keep the CSR extensions consistent with the `CertificateRequest.spec.usages` values. The classical default includes `key encipherment`, which is invalid for ML-DSA.

[RFC 9881 section 5](https://www.rfc-editor.org/rfc/rfc9881.html#section-5) restricts the `keyUsage` extension for ML-DSA subject keys to signature usages. If present, it must contain at least one of `digitalSignature`, `nonRepudiation`, `keyCertSign` or `cRLSign`. It must not contain `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly` or `decipherOnly`.

cmp-issuer enforces this rule for issued chains, CMP response signer chains and signature credentials, including stored certificates used after a restart. It refuses a non-compliant issued certificate and sends a rejecting `certConf` when explicit confirmation is required. RSA or ECDSA subject keys retain their usual usages when signed by an ML-DSA CA.

## Dependencies

The CMP library is pre-v1. [ADR 0001](adr/0001-cmp-library.md) describes the dependency boundary and validation requirements.

## API stability

`certmanager.misiektoja.github.io/v1alpha1` may change before a stable version.

## Related pages

* [Transaction recovery](guide/transaction-recovery.md)
* [Threat model](security/threat-model.md)
