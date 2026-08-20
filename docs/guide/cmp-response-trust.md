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
| Responding authority | matched against `spec.protocol.recipient` |

## The responding authority must be the one you addressed

Trust anchors alone do not say which authority answered. Under a shared enterprise or public root every
subordinate CA chains to the same anchor, so protection verification on its own would accept a response
from any of them.

Every response is therefore also required to be sent by the authority named in `spec.protocol.recipient`.
A response naming a different authority is rejected with `wrongAuthority` and no certificate is
accepted, whichever protection mechanism was used. A response must also use the same protection
mechanism as the request. A signature cannot replace PasswordBasedMac or the reverse.

The comparison requires the same attributes and values, and ignores their order. Certificate tools
disagree about whether to print a distinguished name in encoded order or in the reverse order RFC 4514
defines, so a recipient copied from either kind of output is accepted. A response that omits its sender
name carries nothing to bind to the configured authority and is rejected.

If a server legitimately answers under a different name than the one it is addressed by, set
`spec.protocol.recipient` to the name the server puts in its responses.

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
