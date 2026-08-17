# CMP response trust

`spec.cmpTrust` configures trust anchors used to validate CMP PKIProtection and issued certificate chains.

## Trust Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cmp-trust
type: Opaque
stringData:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ... root or issuing CA ...
    -----END CERTIFICATE-----
```

Reference it from the issuer:

```yaml
spec:
  cmpTrust:
    caSecretRef:
      name: cmp-trust
      key: ca.crt
```

PEM may contain multiple certificates. The signer builds a pool of trust anchors for CMP verification and chain building.

## What CMP trust validates

| Artifact | Validated against CMP trust |
| --- | --- |
| CP PKIProtection signer | yes |
| Protected error responses | yes |
| `pkiConf` when signer is identified | yes |
| `pkiConf` when signer is omitted | retained signer from CP |
| Issued leaf chain | yes, leaf-first order |

## Separate from TLS trust

HTTPS server validation uses `spec.transport.tls.caSecretRef` or system roots. Misconfigured TLS trust does not bypass CMP protection checks, and valid TLS does not substitute for CMP trust.

## Wrong trust behavior

If CMP trust does not include the server's protection CA:

* Response verification fails
* No certificate is accepted
* No partial TLS Secret is written

Configure trust to the CA that signs CMP responses for your server profile, which may differ from the bootstrap identity root.

## Related pages

* [HTTP and HTTPS transport](transport.md)
* [Message protection](message-protection.md)
