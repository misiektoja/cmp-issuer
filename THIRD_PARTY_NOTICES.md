# Third-party notices

cmp-issuer original code is Apache-2.0. The project links to separately licensed Go modules and uses separately licensed build tools.

## Direct runtime dependencies

| Component | Pinned version | License | Use |
| --- | --- | --- | --- |
| github.com/misiektoja/go-pkicmp-ng | `v0.0.2` | Apache-2.0 | CMP ASN.1 types, protection and parsing behind project-owned interfaces |
| github.com/cert-manager/issuer-lib | v0.12.0 | Apache-2.0 | External issuer reconciliation, approval gates, status and retry contracts |
| github.com/cert-manager/cert-manager | v1.21.1 | Apache-2.0 | cert-manager API types and annotation keys, used to read the certificate revision that separates a renewal from a first enrollment |
| github.com/prometheus/client_golang | v1.23.2 | Apache-2.0 | Counter and histogram types for the enrollment metrics, registered on the controller-runtime metrics registry |

go-pkicmp-ng is a maintained derivative of [github.com/tsaarni/go-pkicmp](https://github.com/tsaarni/go-pkicmp) by Tero Saarni, carrying message verification corrections that the published upstream release does not have. It keeps that project's Apache-2.0 license text and records the derivation and its attribution in its own `NOTICE` file. It introduces no additional third-party code and carries the same dependency set as the upstream release it is based on. It is required as an ordinary module, so `go.mod` holds no `replace` directive for it. See [ADR 0001](https://misiektoja.github.io/cmp-issuer/adr/0001-cmp-library/).

This table covers the direct runtime dependencies that carry protocol or controller behavior. Complete license reporting across the whole module graph is automated: `make sbom` produces a CycloneDX bill of materials that records a resolved license for every module in the build. It runs on every push and on a weekly schedule, and the resulting bill of materials is attached to each release. Neither document replaces the license texts distributed by dependency authors.

No ASN.1 module or RFC code component has been copied into the project at this stage. RFC requirements are reimplemented from prose and cited in protocol documentation.
