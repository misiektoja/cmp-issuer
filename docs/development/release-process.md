# Release process

This page describes the intended release workflow. No release has been published yet.

## Versioning

`RELEASE_NOTES.md` tracks `0.1.0` as the initial development release. Future versions follow semantic versioning for user-visible behavior.

Check the latest published GitHub Release on the default branch before choosing the next version.

## Release artifacts

Each release publishes:

| Artifact | Description |
| --- | --- |
| Container image | Multi-arch `linux/amd64` and `linux/arm64` on GitHub Container Registry |
| Provenance attestation | SLSA-style build attestation for the image digest |
| Installer manifest | `dist/install.yaml` from Kustomize |
| Helm chart | Packaged from `charts/chart` and indexed into the chart repository |
| SBOM | CycloneDX at `dist/cmp-issuer.cdx.json` |
| Air-gapped bundle | `cmp-issuer-<version>-airgap.tar.gz` with the image as an OCI archive, the chart, the installer, the notices and an `INSTALL.txt` |

The image is pushed and exported to the OCI archive by a single `make docker-release` build with two
exporters, so the bundled archive is the published image rather than a second build of the same source.
`make release-bundle VERSION=<version>` then assembles the tarball from what is already in `dist`.

## CI workflows

| Workflow | Purpose |
| --- | --- |
| `test.yml` | Unit tests and OpenSSL interoperability |
| `lint.yml` | golangci-lint |
| `docs.yml` | Strict MkDocs build, and publishing the site from the default branch |
| `test-chart.yml` | Helm lint |
| `test-e2e.yml` | Kind e2e suite, once per supported Kubernetes and cert-manager version |
| `interop-ncm.yml` | Enrollment against a hosted Nokia NCM instance, started by hand |
| `supply-chain.yml` | govulncheck, gitleaks, SBOM, image scan |
| `release.yml` | Build and publish on tag (not yet run) |
| `publish-chart.yml` | Add the released chart to the Helm repository index (not yet run) |

## Chart repository

`release.yml` packages the chart and attaches it to a draft GitHub Release. Publishing that release
triggers `publish-chart.yml`, which adds the new version to `charts/index.yaml` on the `gh-pages`
branch, so `helm repo add` picks it up.

The chart archives stay attached to their GitHub Release and the index points at those asset URLs, so
GitHub Pages serves only `index.yaml`. Existing entries are merged rather than replaced, which keeps
older versions installable, and the index lives under `charts/` so the documentation site occupies the
root of the same Pages site.

The first run creates the `gh-pages` branch. GitHub Pages has to be enabled for the repository and
pointed at that branch before the repository URL resolves.

## Documentation site

`docs.yml` runs the strict MkDocs build on every push and pull request. On the default branch it also
publishes the rendered site to the root of the `gh-pages` branch, so the documentation and the chart
repository share one Pages site.

The publishing step replaces the previous documentation, so a page removed from `docs/` disappears from
the site, but it leaves `charts/index.yaml` and `.nojekyll` alone. Both publishers take the `gh-pages`
concurrency group, so a release that lands while a documentation change is publishing waits instead of
racing.

## Pre-release checklist

1. `make test`, `make lint`, `make docs-build`, `make helm-lint`
2. `make test-e2e` when controller or e2e specs changed
3. Update `RELEASE_NOTES.md` with user-facing entries
4. Tag and push only when authorized to publish

## Supply chain verification

Consumers can verify:

* Image digest against the provenance attestation
* Module vulnerabilities with published SBOM and govulncheck results
* Absence of leaked credentials via gitleaks history scan

Details in [Provenance and supply chain](../provenance.md).

## License

Release artifacts contain Apache-2.0 original code plus dependency notices in `THIRD_PARTY_NOTICES.md`.
