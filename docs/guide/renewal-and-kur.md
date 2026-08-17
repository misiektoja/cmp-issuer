# P10CR renewal and KUR roadmap

cmp-issuer today implements **initial enrollment only** through P10CR. cert-manager renewal and CMP Key Update Request (KUR) are distinct concepts.

## cert-manager renewal

When a `Certificate` nears expiry cert-manager may create a new `CertificateRequest` for the same identity. cmp-issuer sends another P10CR with a fresh CSR.

Whether that succeeds depends entirely on the CMP server profile:

| Server behavior | Outcome |
| --- | --- |
| Allows repeat P10CR for the same identity | Renewal may succeed |
| One-time enrollment code (EJBCA client mode) | Fails until the end entity is reset |
| Requires KUR with proof of possession | **Unsupported** today |

cmp-issuer does **not** implement KUR. Repeat P10CR is not KUR even when it happens to work.

## NCM REST renewal

Some Nokia deployments expose certificate renewal through NCM REST APIs. That path is unrelated to CMP KUR and is **Unsupported** by cmp-issuer.

## Planned: true KUR

A future release may implement CMPv2 KUR with CRMF proof of possession. That requires reading the workload private key under strict authorization rules described in [Private-key handling](private-key-handling.md).

## Planned: IR and CRMF

Initial Registration with CRMF (`IR`) is also planned and shares the private-key access design.

## Support matrix

| Operation | Status |
| --- | --- |
| P10CR initial enrollment | Implemented |
| P10CR repeat enrollment | Server dependent, not KUR |
| KUR | Planned |
| IR (CRMF) | Planned |
| NCM REST renewal | Unsupported |

See [Support matrix](../support-matrix.md).
