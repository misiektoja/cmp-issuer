# Credential Secret access

cmp-issuer resolves Secrets through an uncached Kubernetes API reader. Its manager ClusterRole cannot read Secrets.

The installation creates the `cmp-issuer-credential-reader` ClusterRole with only `get` permission for Secrets. A RoleBinding grants that role to the controller ServiceAccount in the controller's own namespace, `cmp-issuer-system` by default. This is the only namespace from which `CMPClusterIssuer` credentials can be read by default.

The chart binds the role in the release namespace and points `--cluster-resource-namespace` at the same namespace, so the permission and the lookup always agree. Moving the lookup with `manager.clusterResourceNamespace` moves the binding with it.

Every namespace that uses a `CMPIssuer` needs a RoleBinding of its own. The binding grants access only inside that namespace, and there are two ways to create it.

## Let the chart create it

Name the namespaces in `credentialNamespaces` when you install:

```bash
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system --create-namespace \
  --set 'credentialNamespaces={team-a,team-b}'
```

The chart creates one `cmp-issuer-credential-reader-rolebinding` per listed namespace. Each namespace must exist before the release is installed or upgraded, and the setting requires `rbac.namespaced=false`, because a RoleBinding in one namespace cannot reference a Role that lives in another.

Authorize a namespace you add later by upgrading with the full list, since `--set` replaces the value rather than appending to it:

```bash
helm upgrade cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --reuse-values \
  --set 'credentialNamespaces={team-a,team-b,team-c}'
```

## Apply the RoleBinding yourself

This is the route for a namespace you would rather not carry in the release values, for one created long after the install, or for the manifest installation, which has no values to set:

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

Both routes create the same grant, so the boundary is unchanged either way: only the namespaces you named are readable, and a namespace added later still needs its own binding. The two bindings carry different names, so listing a namespace that already has a hand-applied binding leaves two identical grants in it. Delete the one you applied when you move a namespace into `credentialNamespaces`.

Under `rbac.namespaced=true` the manager watches only the release namespace, registers only
`CMPIssuer` and uses a Role-based credential reader there. `CMPClusterIssuer` and `CMPIssuer`
resources outside the release namespace are not reconciled. Use the default cluster-scoped mode when
issuers live in more than one namespace.

The RoleBinding does not let the controller read Secrets in any other namespace. Credential references contain no namespace field so an issuer cannot redirect a read across this boundary.

## Workload Secrets for KUR

P10CR does not require the workload private key and never follows cert-manager's private-key annotation.

KUR needs `get` access to the current and staged workload Secrets. The same namespace RoleBinding used for issuer credentials grants that access. For a namespaced `CMPIssuer` the issuer and workload already share a namespace. For a `CMPClusterIssuer` each workload namespace that uses KUR must be listed in `credentialNamespaces` or receive the manual RoleBinding above.

The permission alone does not select a Secret. cmp-issuer first verifies the controlling cert-manager `Certificate`, exact UID, revision, issuer reference, current Secret name and cert-manager provenance, next-key status, staged Secret owner and label plus CSR key equality. An annotation alone cannot authorize a read.

The manager also has cluster-wide `get` permission for `Certificate` resources so it can authenticate this ownership chain. It does not receive list, watch, create, update or delete permission for Certificates.
