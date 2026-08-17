# Credential Secret access

cmp-issuer resolves Secrets through an uncached Kubernetes API reader. Its manager ClusterRole cannot read Secrets.

The installation creates the `cmp-issuer-credential-reader` ClusterRole with only `get` permission for Secrets. A RoleBinding grants that role to the controller ServiceAccount in `cmp-issuer-system`. This is the only namespace from which `CMPClusterIssuer` credentials can be read by default.

An administrator must create a RoleBinding in each namespace that uses a `CMPIssuer`. The binding grants access only inside that namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cmp-issuer-credential-reader
  namespace: application-namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cmp-issuer-credential-reader
subjects:
- kind: ServiceAccount
  name: cmp-issuer-controller-manager
  namespace: cmp-issuer-system
```

The chart can create these bindings for namespaces you already know about, with
`--set 'credentialNamespaces={team-a,team-b}'`. It is the same RoleBinding, so the boundary is
unchanged: only the listed namespaces are readable, and a namespace added later still needs one.

The RoleBinding does not let the controller read Secrets in any other namespace. Credential references contain no namespace field so an issuer cannot redirect a read across this boundary.

P10CR does not require the workload private key. The controller does not interpret `cert-manager.io/private-key-secret-name` and it has no default Secret access in workload namespaces beyond explicitly authorized issuer credential namespaces.
