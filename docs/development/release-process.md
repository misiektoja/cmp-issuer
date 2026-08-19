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
| Installer manifest | `dist/cmp-issuer-<version>-install.yaml` from Kustomize |
| Helm chart | `dist/cmp-issuer-<chart version>.tgz`, packaged from `charts/cmp-issuer` and indexed into the chart repository |
| SBOM | CycloneDX at `dist/cmp-issuer-<version>-sbom.cdx.json` |
| Air-gapped bundle | `cmp-issuer-<version>-airgap.tar.gz`, unpacking to a directory of the same name, with the image as an OCI archive, the chart, the installer, the bill of materials, the notices and an `INSTALL.txt` |

The image is pushed and exported to the OCI archive by a single `make docker-release` build with two
exporters, so the bundled archive is the published image rather than a second build of the same source.
`make release-bundle VERSION=<version>` then assembles the tarball from what is already in `dist`, so
the image export, `build-installer`, `sbom` and the chart packaging all have to have run for the same
version first. The target names whichever one is missing.

Every target that writes a release artifact requires `VERSION` and names its output after it, so no two
releases can share a file name and a file copied out of `dist` still says which release produced it. Set
`VERSION` to the tag carried by `IMG`, for example:

```bash
make docker-archive IMG=ghcr.io/misiektoja/cmp-issuer:v0.1.0 VERSION=v0.1.0
```

The names come from one block at the top of the supply chain section of the `Makefile`, so a new
artifact is named alongside the existing ones rather than inline in the target that writes it. Two of
them do not carry the release tag verbatim:

* The packaged chart is `cmp-issuer-<chart version>.tgz`, without the leading `v`, because a Helm chart
  version has to be bare SemVer. `helm package` also names the directory inside the archive after the
  chart rather than the version, which Helm requires and which no build step here can change.
* `make sbom` run without `VERSION`, as `make supply-chain` and the supply chain workflow do, names the
  bill of materials after the commit it describes instead, since there is no release to name.

## Build identity

The same `VERSION` is stamped into the binary, so a running manager names the release it came from
rather than reporting `development`. `make build` and every image target pass `VERSION`, the commit,
the commit date and `IMG` to the linker, and the Dockerfile forwards them as build arguments. Any
build that does not set `VERSION` falls back to `git describe`, so a development image still names the
tree it was built from.

The manager reports all of it on its first log line and from `/manager --version`, together with the
image, chart and release the install supplied. See
[Troubleshooting](../operations/troubleshooting.md#which-build-is-running).

`buildDate` is the commit date rather than the time of the build, so rebuilding a tag does not change
the binary. The variables the linker stamps live in `internal/version`; renaming one silently disables
the stamp, because the linker ignores an `-X` flag it cannot resolve.

## CI workflows

| Workflow | Purpose |
| --- | --- |
| `test.yml` | Unit tests and OpenSSL interoperability |
| `lint.yml` | golangci-lint and actionlint |
| `codeql.yml` | CodeQL static analysis of the Go code |
| `docs.yml` | Strict MkDocs build, and publishing the site from the default branch |
| `test-chart.yml` | Helm lint |
| `test-e2e.yml` | Kind e2e suite, once per supported Kubernetes and cert-manager version, plus enrollment from a CMP server started in the cluster |
| `ejbca-test-image.yml` | Publishes the preconfigured CMP server image, rebuilding it only when the upstream release moves |
| `interop-ncm.yml` | Enrollment against a hosted Nokia NCM instance, started by hand |
| `supply-chain.yml` | govulncheck, gitleaks, SBOM, image scan |
| `go-patch.yml` | Weekly check for a newer Go patch in the targeted release series, opening the bump as a pull request |
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
2. `make test-e2e` when controller or e2e specs changed, and `make test-e2e-ejbca` when enrollment changed
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
