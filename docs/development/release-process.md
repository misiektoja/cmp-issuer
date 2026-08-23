# Release process

This page describes how a release is built, published and indexed.

## Versioning

`RELEASE_NOTES.md` records every released version. Versions follow semantic versioning for user-visible behavior.

Check the latest published GitHub Release on the default branch before choosing the next version.

## Publishing a release

A release is started by pushing a version tag that is reachable from the default branch, and by nothing
else:

```bash
git push origin v0.1.0
```

`release.yml` builds every artifact, then creates the GitHub Release **as a draft**. Review that draft
and publish it by hand. Publishing it is what indexes the chart, because `publish-chart.yml` triggers on
a published release.

**Never draft a new release from the GitHub UI.** Doing so creates the tag, which starts `release.yml`
against a release that is already published. The workflow refuses before it checks out the code or logs
in to the registry, so nothing is pushed and recovery is cheap, but the release and its tag have to be
removed before the tag can be pushed properly:

```bash
gh release delete v0.1.0 --cleanup-tag --yes
```

Publishing the draft that `release.yml` leaves for you is a different action and is the correct final
step. The hazard is only in drafting a new release yourself.

To rebuild a release whose draft has not been published yet, re-run the workflow or dispatch it with the
same tag. It refreshes the description and replaces the assets. A release that is already published is
never rebuilt, since its image and provenance attestation are in the registry and cannot be withdrawn.

## Release artifacts

Each release publishes:

| Artifact | Description |
| --- | --- |
| Container image | Multi-arch `linux/amd64` and `linux/arm64` on GitHub Container Registry |
| Provenance attestation | Signed Sigstore bundle for the image digest, pushed to GHCR and attached as `cmp-issuer-<version>-provenance.sigstore.json` |
| Source archives | Complete repository as `cmp-issuer-<version>-source.zip` and `cmp-issuer-<version>-source.tar.gz`, including tests, documentation and CI configuration |
| Installer manifest | `dist/cmp-issuer-<version>-install.yaml` from Kustomize |
| Helm chart | `dist/cmp-issuer-<chart version>.tgz`, packaged from `charts/cmp-issuer` and indexed into the chart repository |
| SBOM | CycloneDX at `dist/cmp-issuer-<version>-sbom.cdx.json` |
| Air-gapped bundle | `cmp-issuer-<version>-airgap.tar.gz`, unpacking to a directory of the same name, with the image as an OCI archive, the chart, the installer, the bill of materials, the notices and an `INSTALL.txt` |
| Checksums | SHA-256 manifest at `cmp-issuer-<version>_SHA256SUMS.txt` covering every attached payload |

GitHub build provenance attestations cover the installer, chart, SBOM, air-gapped bundle, both source
archives and the checksum manifest. Verify one with `gh attestation verify <file> --repo
misiektoja/cmp-issuer`. The image has its separate registry attestation and attached Sigstore bundle.

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

After the other payloads have been built, `make release-checksums VERSION=<version>` creates both
complete source archives and the checksum manifest. The release workflow runs it before requesting
artifact provenance and uploading the exact release-named files.

The names come from one block at the top of the supply chain section of the `Makefile`, so a new
artifact is named alongside the existing ones rather than inline in the target that writes it. Two of
them do not carry the release tag verbatim:

* The packaged chart is `cmp-issuer-<chart version>.tgz`, without the leading `v`, because a Helm chart
  version has to be bare SemVer. `helm package` also names the directory inside the archive after the
  chart rather than the version, which Helm requires and which no build step here can change.
* `make sbom` run without `VERSION`, as `make supply-chain` and the supply chain workflow do, names the
  bill of materials after the commit it describes instead, since there is no release to name.

The GitHub release description is the `RELEASE_NOTES.md` section for the version being tagged. It is
extracted before the image is pushed, so a heading that is missing or no longer matches the tag fails
the run while retagging still costs nothing. The release is created as a draft, so the description can
still be edited before anyone sees it.

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
| `scorecard.yml` | OpenSSF repository and supply chain checks, run after successful CodeQL analysis on `main` |
| `docs.yml` | Strict MkDocs build, and publishing the site from the default branch |
| `test-chart.yml` | Helm lint and a complete chart install for chart and build changes |
| `test-e2e.yml` | Kind e2e suite on `dev` and `main`, once per supported Kubernetes and cert-manager version, plus EJBCA enrollment |
| `ejbca-test-image.yml` | Publishes the preconfigured CMP server image, rebuilding it only when the upstream release moves |
| `interop-ncm.yml` | Hosted Nokia NCM enrollment on `dev` and `main`, weekly and by hand |
| `supply-chain.yml` | govulncheck and gitleaks on pull requests, adding SBOM and image scan on trusted branches |
| `go-patch.yml` | Weekly check for a newer Go patch in the targeted release series, opening the bump against `dev` |
| `release.yml` | Build and publish the release artifacts on a version tag |
| `publish-chart.yml` | Add the released chart to the Helm repository index when the release is published |

Pull requests target `dev` and run the fast unit, OpenSSL, lint and supply chain checks. The chart job
runs only when its inputs change. The three-version Kind matrix and EJBCA are deliberately deferred
until the change lands on `dev`, where failures can be fixed before promotion. Pushes to `main` repeat
the trusted-branch checks for the stable code. NCM remains automatic on both trusted branches but never
receives pull request code or fork credentials. Superseded runs are cancelled, except for NCM because
an external enrollment should not be abandoned halfway through.

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

`docs.yml` runs the strict MkDocs build for documentation-related changes on pull requests and pushes
to `dev` and `main`. On the default branch it also publishes the rendered site to the root of the
`gh-pages` branch, so the documentation and the chart repository share one Pages site.

The publishing step replaces the previous documentation, so a page removed from `docs/` disappears from
the site, but it leaves `charts/index.yaml` and `.nojekyll` alone. Both publishers take the `gh-pages`
concurrency group, so a release that lands while a documentation change is publishing waits instead of
racing.

## Pre-release checklist

1. `make test`, `make lint`, `make docs-build`, `make helm-lint`
2. `make test-e2e` when controller or e2e specs changed, and `make test-e2e-ejbca` when enrollment changed
3. Update `RELEASE_NOTES.md` with user-facing entries under a `## [<chart version>]` heading carrying the
   release date, since the release workflow publishes that section as the GitHub release description
4. Refresh `artifacthub.io/changes` in `charts/cmp-issuer/Chart.yaml`, along with any other
   `artifacthub.io` annotation the release changes. Chart metadata is frozen once the version is
   published, so a correction needs a new chart version
5. Point `config/manager/kustomization.yaml` at the image the release will publish, which is what a
   clone applies when it has not run `make build-installer`
6. Tag and push only when authorized to publish, and never create the release from the GitHub UI. See
   [Publishing a release](#publishing-a-release)

## Supply chain verification

Consumers can verify:

* Image digest against the provenance attestation in GHCR or the signed Sigstore bundle attached to the release
* Release payloads against `cmp-issuer-<version>_SHA256SUMS.txt` and their GitHub build provenance attestations
* Module vulnerabilities with published SBOM and govulncheck results
* Absence of leaked credentials via gitleaks history scan

Details in [Provenance and supply chain](../provenance.md).

## License

Release artifacts contain Apache-2.0 original code plus dependency notices in `THIRD_PARTY_NOTICES.md`.
