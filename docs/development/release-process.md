# Release process

This page describes the intended release workflow. No release has been published yet.

## Versioning

The changelog tracks `0.1.0` as the initial development release. Future versions follow semantic versioning for user-visible behavior.

Determine the latest published GitHub Release from the default branch before bumping versions. See repository release policy in project guidance.

## Release artifacts

Each release publishes:

| Artifact | Description |
| --- | --- |
| Container image | Multi-arch `linux/amd64` and `linux/arm64` on GitHub Container Registry |
| Provenance attestation | SLSA-style build attestation for the image digest |
| Installer manifest | `dist/install.yaml` from Kustomize |
| Helm chart | Packaged from `charts/chart` |
| SBOM | CycloneDX at `dist/cmp-issuer.cdx.json` |

## CI workflows

| Workflow | Purpose |
| --- | --- |
| `test.yml` | Unit tests and OpenSSL interoperability |
| `lint.yml` | golangci-lint |
| `docs.yml` | Strict MkDocs build |
| `test-chart.yml` | Helm lint |
| `test-e2e.yml` | Kind e2e suite |
| `supply-chain.yml` | govulncheck, gitleaks, SBOM, image scan |
| `release.yml` | Build and publish on tag (not yet run) |

## Pre-release checklist

1. `make test`, `make lint`, `make docs-build`, `make helm-lint`
2. `make test-e2e` when controller or e2e specs changed
3. Update `CHANGELOG.md` with user-facing entries
4. Tag and push only when authorized to publish

## Supply chain verification

Consumers can verify:

* Image digest against the provenance attestation
* Module vulnerabilities with published SBOM and govulncheck results
* Absence of leaked credentials via gitleaks history scan

Details in [Provenance and supply chain](../provenance.md).

## License

Release artifacts contain GPL-3.0-only original code plus dependency notices in `THIRD_PARTY_NOTICES.md`.
