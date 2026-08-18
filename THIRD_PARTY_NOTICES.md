# Third-party notices

cmp-issuer original code is Apache-2.0. The project links to separately licensed Go modules and uses separately licensed build tools.

## Direct runtime dependencies under review

| Component | Pinned version | License | Use |
| --- | --- | --- | --- |
| github.com/tsaarni/go-pkicmp | `v0.0.0-20260817124344-a18451f3cf35`, supplied by [github.com/misiektoja/go-pkicmp-ng](https://github.com/misiektoja/go-pkicmp-ng) at branch `cmp-hardening` | Apache-2.0 | CMP ASN.1 types, protection and parsing behind project-owned interfaces |
| github.com/cert-manager/issuer-lib | v0.12.0 | Apache-2.0 | External issuer reconciliation, approval gates, status and retry contracts |

go-pkicmp is built from a fork while corrections to its message verification path are pending upstream, so a `replace` directive in `go.mod` redirects the upstream module path to that fork. The fork keeps the upstream module path, copyright notices and Apache-2.0 license text unchanged and introduces no additional third-party code. It carries the same dependency set as the upstream release it is based on. The directive is removed once the corrections are published upstream. See [ADR 0001](docs/adr/0001-cmp-library.md).

This table covers the direct runtime dependencies that carry protocol or controller behavior. Complete license reporting across the whole module graph is automated: `make sbom` produces a CycloneDX bill of materials that records a resolved license for every module in the build. It runs on every push and on a weekly schedule, and the resulting bill of materials is attached to each release. Neither document replaces the license texts distributed by dependency authors.

No ASN.1 module or RFC code component has been copied into the project at this stage. RFC requirements are reimplemented from prose and cited in protocol documentation.
