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

The configured certificates also identify response signers when the server omits them from
`extraCerts`. Response certificates are tried first, then the configured anchors. Every signer must
pass chain, sender and signature validation. Both validation profiles accept this omission, as
described in [message protection](message-protection.md#what-gets-validated).

## Response signer certificates

If the server omits a signer that is not a trust anchor, provide its certificate and any required
intermediates in a separate Secret:

```yaml
spec:
  cmpTrust:
    caSecretRef:
      name: cmp-trust
      key: ca.crt
    signerCertificatesSecretRef:
      name: cmp-response-signers
      key: certificates.pem
```

The selected key contains one or more PEM certificates. The Secret uses the same namespace rules as
the trust Secret. These certificates are tried after response `extraCerts` and configured anchors.
They do not add trust anchors. Every accepted signer must chain to `caSecretRef`, match the response
sender and verify the signature. Both validation profiles allow a configured signer to be omitted
from the response.

The bundle also supplies untrusted intermediates for the issued certificate chain, which must still
terminate at `caSecretRef`. Changing this Secret during an unfinished transaction prevents that
transaction from resuming with the changed configuration.

## What CMP trust validates

| Artifact | Validated against CMP trust |
| --- | --- |
| CP PKIProtection signer | yes |
| Protected error responses | yes |
| `pkiConf` when signer is identified | yes |
| `pkiConf` when signer is omitted | configured certificate or retained transaction signer |
| Issued leaf chain | yes, leaf-first order |
| Responding authority | matched against `spec.protocol.recipient` |

## The responding authority must be the one you addressed

Trust anchors alone do not say which authority answered. Under a shared enterprise or public root every
subordinate CA chains to the same anchor, so protection verification on its own would accept a response
from any of them.

Every response is therefore also required to be sent by the authority named in `spec.protocol.recipient`.
A response naming a different authority is rejected with `wrongAuthority` and no certificate is
accepted, whichever protection mechanism was used.

A MAC can never replace a signature. A signature replaces PasswordBasedMac by default, because many
servers sign every response, and the signer still has to chain to `spec.cmpTrust.caSecretRef` and name
the recipient, so the two rules above still apply to it. Set
`spec.protocol.macResponseProtection` to `Strict` to require MAC-based protection throughout instead.
See [message protection](message-protection.md).

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
