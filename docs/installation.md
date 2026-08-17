# Installation

cmp-issuer requires cert-manager with external issuer support. Install cert-manager first, then install the controller.

## Prerequisites

* A Kubernetes cluster, verified on v1.34
* cert-manager with external issuer support, verified on v1.19 and v1.20
* For namespaced issuers: administrator-created RoleBindings in each workload namespace

## Installer manifest

Build or download `dist/install.yaml`, then apply it:

```bash
make build-installer IMG=<registry>/cmp-issuer:<tag>
kubectl apply -f dist/install.yaml
```

The manifest installs CRDs, RBAC, the controller Deployment in `cmp-issuer-system` and a ClusterRoleBinding that lets the controller read Secrets **only** in `cmp-issuer-system`.

## Helm chart

Install from `charts/chart` when values-driven configuration is preferred:

```bash
helm install cmp-issuer ./charts/chart \
  --namespace cmp-issuer-system \
  --create-namespace
```

Common values:

| Value | Purpose |
| --- | --- |
| `manager.image.repository` and `manager.image.tag` | Controller image and tag |
| `manager.replicas` | Controller replica count |
| `manager.args` | Extra controller flags, for example `--cluster-resource-namespace=<ns>` |
| `rbac.namespaced` | Scope RBAC to the release namespace instead of cluster-wide |
| `crd.enabled` and `crd.keep` | Install CRDs and keep them on uninstall |

Run `make helm-lint` to validate the chart locally.

Both installation paths deploy the same CRDs and controller. Neither grants Secret access in workload namespaces.

## Namespace access for CMPIssuer

Every namespace that hosts a `CMPIssuer` needs a RoleBinding as described in [Credential Secret access](operations/secret-access.md). Without it the issuer stays Not Ready and names the missing authorization.

## Verify the controller

```bash
kubectl -n cmp-issuer-system get deploy,pods
kubectl get crd | grep certmanager.misiektoja.github.io
```

## Create an issuer

Apply credential and trust Secrets, then create a `CMPIssuer` or `CMPClusterIssuer`. Samples live under `config/samples/`. See [CMPIssuer](reference/cmpissuer.md) and [CMPClusterIssuer](reference/cmpclusterissuer.md).

## Issue a certificate

Create a cert-manager `Certificate` that references the issuer:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-tls
spec:
  secretName: example-tls
  issuerRef:
    name: my-cmp-issuer
    kind: CMPIssuer
    group: certmanager.misiektoja.github.io
  commonName: workload.example.com
```

See [Enrollment](guide/enrollment.md) for the full flow.
