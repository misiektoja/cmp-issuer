# Signature protection

Certificate-based signature protection signs CMP messages with a bootstrap identity known to the CMP server.

## Secret format

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

## Issuer configuration

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

## extraCerts layout

cmp-issuer sends the protection end-entity certificate first, followed by configured intermediates. Some servers resolve the signing certificate from `extraCerts` using `senderKID`. NCM requires the end-entity certificate to appear in `extraCerts` for P10CR.

## EJBCA client mode

EJBCA resolves the authenticating certificate from its own database. The signature credential needs only `tls.crt` and `tls.key`; `chainKey` may be omitted.

Client mode enrolls only the identity that owns the authenticating certificate. The requested subject DN must match the registered end entity. A signature-protected issuer therefore issues for its bootstrap identity, not arbitrary workload names, unless the server profile allows otherwise.

## Related pages

* [Message protection](message-protection.md)
* [Tested PKIs](../interoperability/tested-pkis.md)
