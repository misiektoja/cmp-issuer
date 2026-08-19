# cmp-issuer

A vendor-neutral [cert-manager](https://cert-manager.io/) external issuer for Certificate Management
Protocol (CMP) servers.

Point a cert-manager `Certificate` at a `CMPIssuer` and the certificate is enrolled over CMPv2 and
written to the usual TLS Secret, so workloads that already consume cert-manager Secrets need no change.
CMP message protection is mandatory, and the controller never reads the workload private key.

Full documentation is at
[misiektoja.github.io/cmp-issuer](https://misiektoja.github.io/cmp-issuer/).

## Prerequisites

* Kubernetes v1.31 or newer. Verified on v1.34, v1.35 and v1.36
* [cert-manager](https://cert-manager.io/docs/installation/) with external issuer support. Verified on
  v1.19, v1.20 and v1.21
* Helm v3
* A CMP server, plus its endpoint URL, recipient DN, a credential and the CA certificate that signs its
  CMP responses

## Install

```bash
helm repo add cmp-issuer https://misiektoja.github.io/cmp-issuer/charts
helm repo update
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --create-namespace
```

This installs the CRDs, the controller and the permission cert-manager needs before it will approve
requests for this issuer type.

[Getting started](https://misiektoja.github.io/cmp-issuer/getting-started/) goes from here to an issued
certificate. [Installation](https://misiektoja.github.io/cmp-issuer/installation/) covers the other
install paths and what happens to the CRDs on uninstall.

## The three values that decide whether issuance works

Everything else has a working default. These do not.

### `credentialNamespaces`

The controller has **no cluster-wide Secret access**. Each namespace hosting a `CMPIssuer` has to be
authorized explicitly, and listing it here creates that RoleBinding instead of you applying it by hand.

```yaml
credentialNamespaces:
  - team-a
  - team-b
```

Every entry widens the boundary the project is built around, so name only namespaces you have already
decided on. Each must exist before the release is installed or upgraded. A `CMPClusterIssuer` needs
none of this, since it reads credentials only from the release namespace. Requires `rbac.namespaced` to
be `false`, because a RoleBinding in another namespace cannot reference a Role that lives in this one.
See [credential Secret access](https://misiektoja.github.io/cmp-issuer/operations/secret-access/).

### `certManagerApproval`

cert-manager's built-in approver acts only on issuer types it holds `approve` permission for, and it
**reports nothing when it lacks that permission**. Without this, every `CertificateRequest` referencing
a `CMPIssuer` stays pending forever, no CMP message is sent and no error appears anywhere.

It defaults to `create: true`. Set `certManagerApproval.create=false` when approver-policy makes the
decision instead, and adjust `serviceAccountName` and `namespace` when cert-manager does not run as
`cert-manager` in namespace `cert-manager`.

### `manager.image.repository`

Defaults to `ghcr.io/misiektoja/cmp-issuer` at the chart's `appVersion`. Set it to your own registry
when mirroring the image, or to a `repository@sha256:...` reference to pin a digest, in which case
`manager.image.tag` is ignored.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `manager.enabled` | `true` | Install the controller. Set to `false` for a CRD-only install |
| `manager.replicas` | `1` | Controller replicas. Leader election is enabled by default |
| `manager.image.repository` | `ghcr.io/misiektoja/cmp-issuer` | Controller image, or a digest reference |
| `manager.image.tag` | `Chart.appVersion` | Image tag |
| `manager.image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `manager.args` | `["--leader-elect"]` | Extra controller arguments |
| `manager.clusterResourceNamespace` | release namespace | Namespace `CMPClusterIssuer` credential Secrets are read from |
| `manager.imagePullSecrets` | unset | Pull secrets for a private registry |
| `manager.extraEnv` | unset | Extra environment variables for the controller container |
| `manager.resources` | 500m / 128Mi limits, 10m / 64Mi requests | Controller resources |
| `manager.podSecurityContext`, `manager.securityContext` | non-root, no privilege escalation, all capabilities dropped, read-only root filesystem | Security context |
| `manager.affinity`, `manager.nodeSelector`, `manager.tolerations`, `manager.topologySpreadConstraints` | empty | Scheduling |
| `manager.priorityClassName`, `manager.strategy`, `manager.terminationGracePeriodSeconds` | unset, unset, `10` | Deployment tuning |
| `manager.labels`, `manager.annotations`, `manager.pod.labels`, `manager.pod.annotations` | unset | Custom metadata |
| `credentialNamespaces` | `[]` | Namespaces whose credential and trust Secrets the controller may read |
| `certManagerApproval.create` | `true` | Grant cert-manager's approver permission over this issuer type |
| `certManagerApproval.serviceAccountName` | `cert-manager` | ServiceAccount the cert-manager controller runs as |
| `certManagerApproval.namespace` | `cert-manager` | Namespace cert-manager is installed in |
| `crd.enabled` | `true` | Install the CRDs with the chart |
| `crd.keep` | `true` | Keep the CRDs on `helm uninstall`, so removing the release cannot delete your issuers and transactions |
| `rbac.namespaced` | `false` | Use Role and RoleBinding in the release namespace instead of cluster-scoped |
| `rbac.helpers.enabled` | `true` | Install convenience admin, editor and viewer roles for the CRDs, the same ones the installer manifest creates |
| `serviceAccount.enabled` | `true` | Create the controller ServiceAccount |
| `serviceAccount.name` | unset | Existing ServiceAccount to use when `enabled` is `false` |
| `logging.level` | `info` | `debug`, `info`, `error` or an integer. `info` logs one line per enrollment outcome |
| `logging.stacktraceLevel` | `panic` | Level at and above which a stack trace is attached |
| `logging.encoder` | `json` | `json` for log collectors, `console` to read by eye |
| `metrics.enabled` | `true` | Expose the `/metrics` endpoint |
| `metrics.port` | `8443` | Metrics port |
| `metrics.secure` | `true` | Serve metrics over HTTPS, authenticated with a `TokenReview` and authorized with a `SubjectAccessReview`, and create the RBAC both need. `false` serves plain HTTP to anything that reaches the port |
| `certManager.enabled` | `false` | Use cert-manager for the metrics endpoint certificate |
| `prometheus.enabled` | `false` | Create a Prometheus `ServiceMonitor`. Needs prometheus-operator |
| `networkPolicy.enabled` | `false` | Restrict ingress to the controller |
| `nameOverride`, `fullnameOverride` | unset | Override the generated resource names |

`values.yaml` carries a comment on every key, including the ones commented out above.

## Upgrading

CRDs ship inside the chart, so `helm upgrade` updates them. They are annotated to survive
`helm uninstall`, so removing the release cannot delete your `CMPIssuer`, `CMPClusterIssuer` and
`CMPTransaction` resources. Delete them by hand when you mean to.

Changing `rbac.namespaced` on an existing release fails, because Kubernetes does not allow the
`roleRef` of a binding to change. Delete the affected RoleBinding and ClusterRoleBinding first, or
reinstall the release.

## Troubleshooting

The two symptoms that account for most first installs:

| Symptom | Cause |
| --- | --- |
| `CertificateRequest` stays pending with no error and no events | cert-manager's approver lacks permission. See `certManagerApproval` above |
| Issuer reports it cannot read its credential Secret | The namespace is not listed in `credentialNamespaces` |

The manager names its own build, image, chart and release on its first log line, and `/manager
--version` prints the same thing, so a bug report can say exactly what was running.

[Troubleshooting](https://misiektoja.github.io/cmp-issuer/operations/troubleshooting/) is organized by
the symptom you actually see.

## Source and license

Source and issues: [github.com/misiektoja/cmp-issuer](https://github.com/misiektoja/cmp-issuer).
Original cmp-issuer code is licensed under Apache-2.0. Dependencies retain their own licenses.
