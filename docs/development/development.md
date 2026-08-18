# Development

Guide for building and running cmp-issuer from source.

## Prerequisites

* Go 1.26 or later
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

## Common commands

```bash
make test          # Unit and envtest suites
make lint          # golangci-lint v2.12.2
make run           # Run controller locally against current kubeconfig
make manifests     # Regenerate CRDs and RBAC from markers
make generate      # Regenerate DeepCopy code
make docs-build    # Strict MkDocs build
make helm-lint     # Helm chart lint
```

After editing `*_types.go` run `make manifests generate`. After editing Go sources run `make lint-fix test`.

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

`make build-installer` rewrites `config/manager/kustomization.yaml` image tags. Restore with `git checkout -- config/manager/kustomization.yaml` when finished if a clean worktree is required.

## API changes

Use kubebuilder CLI to scaffold new APIs or webhooks. Do not delete `// +kubebuilder:scaffold:*` markers.

The API is `v1alpha1` and may change before a stable release.

## Protocol layer

CMP encoding and protection sit behind project-owned interfaces. go-pkicmp types must not appear in CRDs or public packages. See [ADR 0001](../adr/0001-cmp-library.md).

## License

Original code is Apache-2.0. Dependencies retain their own licenses. See `THIRD_PARTY_NOTICES.md`.
