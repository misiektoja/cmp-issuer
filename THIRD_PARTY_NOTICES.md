# Third-party notices

cmp-issuer original code is Apache-2.0. The project links to separately licensed Go modules and uses separately licensed build tools.

## Direct runtime dependencies under review

| Component | Pinned version | License | Use |
| --- | --- | --- | --- |
| github.com/tsaarni/go-pkicmp | commit `66dd5e04fc1fe56f3724eba145787f0394a91c69` | Apache-2.0 | CMP ASN.1 types, protection and parsing behind project-owned interfaces |
| github.com/cert-manager/issuer-lib | v0.12.0 | Apache-2.0 | External issuer reconciliation, approval gates, status and retry contracts |

Automated complete-module license reporting remains required before a release. This manually reviewed notice does not replace the license texts distributed by dependency authors.

No ASN.1 module or RFC code component has been copied into the project at this stage. RFC requirements are reimplemented from prose and cited in protocol documentation.
