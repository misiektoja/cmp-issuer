# Development

Guide for building and running cmp-issuer from source.

## Prerequisites

* Go 1.26.7 or later, the minimum `go.mod` declares so every build carries the standard library security fixes from that patch
* Docker or Podman for image builds
* Kubebuilder v4.15 for API scaffolding (optional for day-to-day work)
* Python with MkDocs dependencies for documentation (`make docs-deps`)

## Repository layout

The project follows the standard Kubebuilder layout. Generated files carry `// +kubebuilder:scaffold:*` markers that the CLI uses as insertion points, so they must be left in place.

Key directories:

| Path | Content |
| --- | --- |
| `api/v1alpha1/` | CRD types and markers |
| `internal/controller/` | Reconciliation and signer |
| `internal/protocol/` | CMP adapter |
| `config/` | Kustomize and Helm inputs |
| `charts/cmp-issuer/` | Helm chart |
| `docs/` | MkDocs site |
| `test/e2e/` | Kind-based controller tests |
| `test/e2e/ejbca/` | Preconfigured CMP server image that the enrollment tests start |
| `test/workflows/` | Supply chain checks over the GitHub Actions workflow definitions |

## Common commands

```bash
make test            # Unit and envtest suites
make test-e2e        # Kind-based controller tests
make test-e2e-ejbca  # Enrollment from a CMP server started in the test cluster
make lint            # golangci-lint v2.12.2 and actionlint v1.7.12
make run             # Run controller locally against current kubeconfig
make manifests       # Regenerate CRDs and RBAC from markers
make generate        # Regenerate DeepCopy code
make docs-build      # Strict MkDocs build
make helm-lint       # Helm chart lint
make clean           # Remove build, test and documentation outputs
```

`make clean` keeps the tool binaries downloaded into `bin/`, so the next build does not re-download the toolchain. `make clean-tools` removes those as well and `make clean-all` does both.

After editing `*_types.go` run `make manifests generate`. After editing Go sources run `make lint-fix test`.

`make lint` lints the GitHub Actions workflows as well, so a mistyped trigger or a bad expression is reported before a push rather than by a workflow run that has already started. `lint-fix` and `lint-config` stay Go-only. actionlint runs shellcheck over `run:` blocks when shellcheck is on PATH, which it is on the GitHub-hosted runners, so install it locally to see the same findings CI does.

## Local controller

```bash
make run
```

Uses the kubeconfig current context. Do not point at production clusters without understanding issuer side effects.

## Image build

```bash
export IMG=localhost/cmp-issuer:dev
make docker-build IMG=$IMG
make deploy IMG=$IMG
```

`make build-installer` needs both `IMG` and `VERSION`, since it writes the release-named
`dist/cmp-issuer-<version>-install.yaml`. It also rewrites `config/manager/kustomization.yaml` image
tags. Restore with `git checkout -- config/manager/kustomization.yaml` when finished if a clean worktree
is required.

## Chart regeneration

The chart directory is named after the chart, `charts/cmp-issuer`, so that a clone matches the packaged
artifact. The kubebuilder Helm plugin does not support that name. It writes to `<output>/chart`, where
`output` is the value in `PROJECT`, so `kubebuilder edit --plugins=helm.kubebuilder.io/v2-alpha` scaffolds
a fresh `charts/chart` beside the real chart instead of updating it. Nothing packages or lints that
directory, so regenerated CRD and RBAC templates would be silently left out of the release.

If you regenerate, move the refreshed templates into `charts/cmp-issuer` and delete `charts/chart`.
`make helm-lint` fails while `charts/chart` exists, so CI catches a regeneration that was left in place.
`Chart.yaml` is never overwritten by the plugin, so the metadata in the real chart is safe either way,
including the `appVersion` that has to keep matching the published image tag.

The plugin reads the manifest path recorded in `PROJECT`, which is `dist/install.yaml`, while
`make build-installer` writes the release-named `dist/cmp-issuer-<version>-install.yaml`. Copy the
manifest to `dist/install.yaml` before regenerating. `PROJECT` is tool-generated and records one fixed
path, so it is left alone rather than pointed at a name that changes every release.

## API changes

Use kubebuilder CLI to scaffold new APIs or webhooks. Do not delete `// +kubebuilder:scaffold:*` markers.

The API is `v1alpha1` and may change before a stable release.

## Protocol layer

CMP encoding and protection sit behind project-owned interfaces. Library types must not appear in CRDs or public packages. See [ADR 0001](../adr/0001-cmp-library.md).

The library is [go-pkicmp-ng](https://github.com/misiektoja/go-pkicmp-ng), required like any other module, so no `replace` directive is involved and every build route resolves the same version. Advance the pin with:

```sh
go get github.com/misiektoja/go-pkicmp-ng@<version>
go mod tidy
```

Rerun `make test` and one enrollment against a real CMP server afterwards, since the library sits directly in the verification path.

## License

Original code is Apache-2.0. Dependencies retain their own licenses. See `THIRD_PARTY_NOTICES.md`.
