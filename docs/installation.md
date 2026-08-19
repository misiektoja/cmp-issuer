# Installation

cmp-issuer runs as a controller alongside cert-manager. Install cert-manager first, then the controller,
then grant the two permissions described below.

If you are installing for the first time, follow [Getting started](getting-started.md) instead. It
covers these steps in order and ends with an issued certificate.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Kubernetes | Verified on v1.34, v1.35 and v1.36 |
| cert-manager with external issuer support | Verified on v1.19, v1.20 and v1.21 |
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

Every release attaches a packaged chart, which is useful offline or behind a mirror. Its version has no
leading `v`, because a Helm chart version has to be bare SemVer:

```bash
helm install cmp-issuer ./cmp-issuer-<chart version>.tgz \
  --namespace cmp-issuer-system \
  --create-namespace
```

### From a clone

Use this when you are modifying the chart itself:

```bash
helm install cmp-issuer ./charts/cmp-issuer \
  --namespace cmp-issuer-system \
  --create-namespace
```

### Common values

| Value | Purpose |
| --- | --- |
| `manager.image.repository` and `manager.image.tag` | Controller image and tag. Defaults to `ghcr.io/misiektoja/cmp-issuer` at the chart's `appVersion`. Set the repository to a `name@sha256:...` reference to pin a digest, in which case the tag is ignored |
| `manager.replicas` | Controller replica count |
| `manager.args` | Extra controller flags |
| `manager.clusterResourceNamespace` | Namespace `CMPClusterIssuer` credential Secrets are read from. Defaults to the release namespace, and a different value also gets a credential reader RoleBinding |
| `rbac.namespaced` | Scope RBAC to the release namespace instead of cluster-wide. Changing it on an existing release needs the existing bindings deleted first, since Kubernetes does not allow a `roleRef` to change |
| `rbac.helpers.enabled` | Install the admin, editor and viewer roles for the issuer kinds, default `true`. They bind to nobody until you create a binding, and the manifest path always installs them |
| `crd.enabled` | Install the CRDs with the chart, default `true` |
| `crd.keep` | Keep the CRDs when the release is uninstalled, default `true` |
| `certManagerApproval.create` | Let cert-manager approve requests for this issuer type, default `true` |
| `certManagerApproval.serviceAccountName` and `.namespace` | Where cert-manager runs, default `cert-manager` in `cert-manager` |
| `credentialNamespaces` | Namespaces to pre-authorize for `CMPIssuer` credential reads, default empty |
| `logging.level`, `.stacktraceLevel`, `.encoder` | Controller log verbosity, stack traces and format |

## Install with the manifest

Every release also attaches a self-contained `cmp-issuer-<version>-install.yaml`:

```bash
kubectl apply -f cmp-issuer-<version>-install.yaml
```

It installs the same CRDs, RBAC, cert-manager approval permission and controller Deployment in
`cmp-issuer-system`, plus a RoleBinding that lets the controller read Secrets **only** in
`cmp-issuer-system`. Neither installation path grants Secret access in workload namespaces on its own,
and the manifest has no values to set, so a `CMPIssuer` namespace is authorized by applying the
RoleBinding yourself.

The metrics endpoint serves HTTPS and authorizes every scrape, the same as the chart. It is the one
place where the two paths differ in what they offer: the chart can have cert-manager issue the metrics
serving certificate through `metrics.tls.certManager.enabled`, and the released manifest is built
without it, so the endpoint presents a certificate the controller generates for `localhost` and a
scraper has to skip verification. To get the issued certificate on this path, build the manifest from a
checkout and uncomment the sections marked `CERTMANAGER`, `METRICS-WITH-CERTS` and
`PROMETHEUS-WITH-CERTS` in `config/default/kustomization.yaml` and
`config/prometheus/kustomization.yaml`, following the notes there, then run `make build-installer`.

## Install without registry access

Every release attaches `cmp-issuer-<version>-airgap.tar.gz`, which carries everything an air-gapped
cluster needs: the manager image as a multi-architecture OCI archive, the packaged chart, the installer
manifest, the bill of materials, the licence and notices, and an `INSTALL.txt` repeating the two
commands below. The bill of materials travels with the bundle so a cluster with no route to the release
page can still answer what the image was built from.

It unpacks into `cmp-issuer-<version>-airgap/`, and every file inside carries the version too, so two
releases can be unpacked side by side and a file copied out of either one still names the release it
came from:

```text
cmp-issuer-<version>-airgap/
  images/cmp-issuer-<version>-image.tar    manager image as an OCI archive
  charts/cmp-issuer-<chart version>.tgz    packaged Helm chart
  cmp-issuer-<version>-install.yaml        self-contained manifest install
  cmp-issuer-<version>-sbom.cdx.json       CycloneDX bill of materials
  INSTALL.txt  README.md  RELEASE_NOTES.md  LICENSE  THIRD_PARTY_NOTICES.md
```

The chart is the one file named without the leading `v`, because a Helm chart version has to be bare
SemVer. It is otherwise the same version as everything else in the bundle.

Copy the image into a registry your cluster can reach:

```bash
skopeo copy --all oci-archive:images/cmp-issuer-<version>-image.tar docker://<registry>/cmp-issuer:<version>
```

Import it straight into each node's container runtime instead when you have no registry at all:

```bash
ctr --namespace k8s.io images import images/cmp-issuer-<version>-image.tar
```

Then install from the bundled chart, pointing it at wherever the image now lives:

```bash
helm install cmp-issuer charts/cmp-issuer-<chart version>.tgz --namespace cmp-issuer-system --create-namespace --set manager.image.repository=<registry>/cmp-issuer
```

The archive holds the image that was published, exported from the same build rather than rebuilt, so its
digest matches the one covered by the release provenance attestation described in
[Provenance and supply chain](provenance.md).

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

## cert-manager approval

cert-manager's built-in approver acts only on issuer types it holds explicit permission for, and it
reports nothing when it lacks that permission, so a `CertificateRequest` would simply stay pending
forever. **Both installation paths grant that permission for you**, by creating a ClusterRole with
`approve` on `signers` for `cmpissuers` and `cmpclusterissuers`, bound to the cert-manager controller.

The binding assumes the upstream default, the `cert-manager` ServiceAccount in the `cert-manager`
namespace. Point it elsewhere when your installation differs:

```bash
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system --create-namespace \
  --set certManagerApproval.serviceAccountName=<name> \
  --set certManagerApproval.namespace=<namespace>
```

Turn it off entirely when [approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/)
makes the decision instead, and express the same rule in a `CertificateRequestPolicy`:

```bash
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system --create-namespace \
  --set certManagerApproval.create=false
```

For the manifest path, edit or remove the `cmp-issuer-cert-manager-approver` ClusterRole and its
binding. Both installation paths name it the same way.

## Namespace access for CMPIssuer

The controller has no cluster-wide Secret access. Every namespace hosting a `CMPIssuer` needs a
RoleBinding granting it the credential reader role there. Without it the issuer stays Not Ready and
names the missing authorization. Both routes below create the same grant, described in
[Credential Secret access](operations/secret-access.md).

### Let the chart create the binding

List the namespaces in `credentialNamespaces`, at install time or in a later upgrade:

```bash
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system --create-namespace \
  --set 'credentialNamespaces={team-a,team-b}'
```

```bash
helm upgrade cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --reuse-values \
  --set 'credentialNamespaces={team-a,team-b}'
```

Each listed namespace must exist before the release is installed or upgraded, and each entry widens the
boundary this project is built around, so name only the namespaces you have decided on. An upgrade has
to carry the whole list, since `--set` replaces the value rather than appending to it. This setting
requires `rbac.namespaced=false`, because a RoleBinding in one namespace cannot reference a Role that
lives in another.

### Apply the binding yourself

Applying the RoleBinding directly suits a namespace you do not want recorded in the release values, one
created long after the install, and the manifest installation, which has no values to set. The manifest
is in [Credential Secret access](operations/secret-access.md#apply-the-rolebinding-yourself).

The chart names its binding `cmp-issuer-credential-reader-rolebinding`, so a hand-applied binding under
a different name is not adopted or replaced by a later upgrade. Delete yours if you move the same
namespace into `credentialNamespaces`, or the namespace ends up with two identical grants.

A `CMPClusterIssuer` reads its credentials only from the controller's cluster resource namespace and
needs no per-namespace binding.

## Verify the installation

```bash
kubectl -n cmp-issuer-system get deploy,pods
kubectl get crd | grep certmanager.misiektoja.github.io
```

The manager names its own build on its first log line, so this is also how you confirm which release,
commit and image are actually running:

```bash
kubectl -n cmp-issuer-system logs deploy/cmp-issuer-controller-manager | head -1
```

A Helm install adds the chart and release name to that line. The same output is available from
`/manager --version` inside the container. See
[Which build is running](operations/troubleshooting.md#which-build-is-running).

## Next

Create Secrets and an issuer, then request a certificate. [Getting started](getting-started.md) shows
the whole sequence, and the [CMPIssuer reference](reference/cmpissuer.md) documents every field. Samples
live under `config/samples/`.
