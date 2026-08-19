# P10CR renewal and KUR roadmap

cmp-issuer implements enrollment through P10CR and renews the same way, by sending a fresh P10CR. It implements **no CMP Key Update Request**, so cert-manager renewal and KUR stay distinct concepts here.

## cert-manager renewal

When a `Certificate` nears expiry cert-manager may create a new `CertificateRequest` for the same identity. cmp-issuer sends another P10CR with a fresh CSR.

Whether that succeeds depends entirely on the CMP server profile:

| Server behavior | Outcome |
| --- | --- |
| Allows repeat P10CR for the same identity | Renewal succeeds |
| One-time enrollment code (EJBCA client mode) | Fails until the end entity is reset |
| Requires KUR with proof of possession | **Unsupported** today |

cmp-issuer does **not** implement KUR. Repeat P10CR is not KUR even when it works.

### Both private key rotation policies work where the server allows re-enrollment

Renewal was exercised against Nokia NCM 26.7 through cert-manager, with `cmctl renew`, for both values of `privateKey.rotationPolicy`:

| `rotationPolicy` | What the renewal sends | Result |
| --- | --- | --- |
| `Always` | A new key, so a new public key in the CSR | New certificate, new serial |
| `Never` | The existing key, so the same public key in the CSR | New certificate, new serial |

Each renewal is a **new CMP transaction with a fresh identifier**, not a repeat of the earlier one, which is why it does not draw the `transactionIdInUse` refusal that an actual retransmission gets. See [transaction recovery](transaction-recovery.md) for that distinction.

The controller reads no private key in either case. Under `Never` cert-manager reuses the key it already holds and signs the new CSR itself, exactly as it does for the first enrollment.

A server whose profile authorizes enrollment once per identity refuses the second request. That is a property of the profile, not of cmp-issuer, and the failure is reported as a CMP rejection with the server's own `failInfo`.

## Nokia NCM REST renewal

Some Nokia deployments expose certificate renewal through NCM REST APIs. That path is unrelated to CMP KUR and is **Unsupported** by cmp-issuer.

## Planned: true KUR

A future release may implement CMPv2 KUR with CRMF proof of possession. That requires reading the workload private key under strict authorization rules described in [Private-key handling](private-key-handling.md).

## Planned: IR and CRMF

Initial Registration with CRMF (`IR`) is also planned and shares the private-key access design.

## Support matrix

| Operation | Status |
| --- | --- |
| P10CR initial enrollment | Implemented |
| P10CR repeat enrollment | Server dependent, not KUR. Verified against NCM 26.7 for both rotation policies |
| KUR | Planned |
| IR (CRMF) | Planned |
| Nokia NCM REST renewal | Unsupported |

See [Support matrix](../support-matrix.md).
