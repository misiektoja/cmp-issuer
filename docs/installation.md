# Installation

cmp-issuer runs as a controller alongside cert-manager. Install cert-manager first, then the controller,
then grant the two permissions described below.

If you are installing for the first time, follow [Getting started](getting-started.md) instead. It
covers these steps in order and ends with an issued certificate.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Kubernetes | Verified on v1.34 |
| cert-manager with external issuer support | Verified on v1.19 and v1.20 |
| Helm v3 | Only for the chart installation path |

## Install with Helm

The chart is published as a Helm repository:

```bash
helm repo add cmp-issuer https://misiektoja.github.io/cmp-issuer/charts
helm repo update
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --create-namespace
```

List the available chart versions with `helm search repo cmp-issuer -l`.

### From a packaged chart

Every release attaches a packaged chart, which is useful offline or behind a mirror:

```bash
helm install cmp-issuer ./cmp-issuer-<version>.tgz \
  --namespace cmp-issuer-system \
  --create-namespace
```

### From a clone

Use this when you are modifying the chart itself:

```bash
helm install cmp-issuer ./charts/chart \
  --namespace cmp-issuer-system \
  --create-namespace
```

### Common values

| Value | Purpose |
| --- | --- |
| `manager.image.repository` and `manager.image.tag` | Controller image and tag |
| `manager.replicas` | Controller replica count |
| `manager.args` | Extra controller flags, for example `--cluster-resource-namespace=<ns>` |
| `rbac.namespaced` | Scope RBAC to the release namespace instead of cluster-wide |
| `crd.enabled` | Install the CRDs with the chart, default `true` |
| `crd.keep` | Keep the CRDs when the release is uninstalled, default `true` |

## Install with the manifest

Every release also attaches a self-contained `install.yaml`:

```bash
kubectl apply -f install.yaml
```

It installs the same CRDs, RBAC and controller Deployment in `cmp-issuer-system`, and a
ClusterRoleBinding that lets the controller read Secrets **only** in `cmp-issuer-system`. Neither
installation path grants Secret access in workload namespaces.

## Custom resource definitions

The CRDs ship inside the chart rather than in Helm's separate `crds/` directory, so `helm upgrade`
updates them along with everything else. Helm never upgrades or removes anything placed in `crds/`,
which would leave a new controller running against an old schema.

`crd.keep` defaults to `true`, which marks the CRDs with `helm.sh/resource-policy: keep`. **The CRDs
therefore survive `helm uninstall` on purpose.** Deleting a CRD deletes every object of that kind, so an
uninstall would otherwise destroy all of your `CMPIssuer`, `CMPClusterIssuer` and `CMPTransaction`
resources, including issuers that are in use.

Remove them deliberately when you are certain, after uninstalling the release:

```bash
kubectl delete crd \
  cmpissuers.certmanager.misiektoja.github.io \
  cmpclusterissuers.certmanager.misiektoja.github.io \
  cmptransactions.certmanager.misiektoja.github.io
```

Set `crd.enabled=false` if you manage the CRDs separately, for example when a cluster administrator
applies them ahead of the release.

## Let cert-manager approve requests for cmp-issuer

cert-manager's built-in approver approves requests only for issuer types it has explicit permission
for. Without this permission every `CertificateRequest` referencing a `CMPIssuer` stays pending, no
error is reported and no CMP message is sent.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-controller-approve-cmp-issuer
rules:
- apiGroups: ["cert-manager.io"]
  resources: ["signers"]
  verbs: ["approve"]
  resourceNames:
  - "cmpissuers.certmanager.misiektoja.github.io/*"
  - "cmpclusterissuers.certmanager.misiektoja.github.io/*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-controller-approve-cmp-issuer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-controller-approve-cmp-issuer
subjects:
- kind: ServiceAccount
  name: cert-manager
  namespace: cert-manager
```

Adjust the ServiceAccount to match your cert-manager installation. If you use approver-policy, express
the same decision in a `CertificateRequestPolicy` instead.

## Namespace access for CMPIssuer

Every namespace hosting a `CMPIssuer` needs a RoleBinding, described in
[Credential Secret access](operations/secret-access.md). Without it the issuer stays Not Ready and names
the missing authorization.

A `CMPClusterIssuer` reads its credentials only from the controller's cluster resource namespace and
needs no per-namespace binding.

## Verify the installation

```bash
kubectl -n cmp-issuer-system get deploy,pods
kubectl get crd | grep certmanager.misiektoja.github.io
```

## Next

Create Secrets and an issuer, then request a certificate. [Getting started](getting-started.md) shows
the whole sequence, and the [CMPIssuer reference](reference/cmpissuer.md) documents every field. Samples
live under `config/samples/`.
