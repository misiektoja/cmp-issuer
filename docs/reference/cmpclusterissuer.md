# CMPClusterIssuer

`CMPClusterIssuer` is a cluster-scoped cert-manager issuer. Credential and trust Secrets are read from the controller **cluster resource namespace**, not from the workload namespace.

## API

| Field | Value |
| --- | --- |
| API group | `certmanager.misiektoja.github.io` |
| Version | `v1alpha1` |
| Kind | `CMPClusterIssuer` |
| Scope | Cluster |
| cert-manager issuer type | `cmpclusterissuers.certmanager.misiektoja.github.io` |

## Cluster resource namespace

The controller flag `--cluster-resource-namespace` selects where credential Secrets live. The default installation uses `cmp-issuer-system`. With the Helm chart, override it by adding the flag to `manager.args`.

Store PBM credentials, signature bootstrap material and CMP trust anchors in that namespace. Reference them by name only in the issuer spec.

## Example

```yaml
apiVersion: certmanager.misiektoja.github.io/v1alpha1
kind: CMPClusterIssuer
metadata:
  name: example
spec:
  endpoint:
    url: http://cmp.example.net/pkix/
    timeout: 30s
    maxResponseSize: 1048576
  protocol:
    version: 2
    initialEnrollment: P10CR
    recipient: CN=Example CA,O=Example
    confirmation: Explicit
  protection:
    type: Signature
    signature:
      secretRef:
        name: cmp-signature-credentials
      certificateKey: tls.crt
      privateKeyKey: tls.key
      chainKey: ca.crt
  cmpTrust:
    caSecretRef:
      name: cmp-trust
      key: ca.crt
```

## Spec and status

The `spec` and `status` schemas are identical to [CMPIssuer](cmpissuer.md). Only scope and Secret resolution differ.

## When to use which issuer

| Issuer | Credential location | Typical use |
| --- | --- | --- |
| `CMPIssuer` | Same namespace as the issuer | Tenant or application isolation |
| `CMPClusterIssuer` | Cluster resource namespace | Shared CMP endpoint and credentials |

## RBAC

The base install grants Secret read access in `cmp-issuer-system` through a RoleBinding to the `cmp-issuer-credential-reader` ClusterRole. No per-namespace RoleBinding is required for cluster issuers.

## Related pages

* [CMPIssuer](cmpissuer.md)
* [Credential Secret access](../operations/secret-access.md)
