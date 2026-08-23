# Getting help

Start with the [documentation](https://misiektoja.github.io/cmp-issuer/). [Getting started](https://misiektoja.github.io/cmp-issuer/getting-started/), [Installation](https://misiektoja.github.io/cmp-issuer/installation/), the [support matrix](https://misiektoja.github.io/cmp-issuer/support-matrix/) and [Troubleshooting](https://misiektoja.github.io/cmp-issuer/operations/troubleshooting/) cover the common setup and enrollment problems.

## Check your deployment first

Confirm which build is running and collect the issuer, request and transaction state before asking for help:

```bash
kubectl exec -n cmp-issuer-system deploy/cmp-issuer-controller-manager -- /manager --version
kubectl describe cmpissuer <name> -n <namespace>
kubectl describe certificaterequest <name> -n <namespace>
kubectl get cmptransactions -A
kubectl logs -n cmp-issuer-system deploy/cmp-issuer-controller-manager -c manager
```

Use `cmpclusterissuer` instead of `cmpissuer` for a cluster-scoped issuer. [Troubleshooting](https://misiektoja.github.io/cmp-issuer/operations/troubleshooting/) explains the conditions, transaction phases and log fields.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question or discuss an idea | [Discussions](https://github.com/misiektoja/cmp-issuer/discussions) |
| Report something broken | [Bug report](https://github.com/misiektoja/cmp-issuer/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/cmp-issuer/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/cmp-issuer/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the cmp-issuer version, installation method, Kubernetes and cert-manager versions, issuer kind, CMP server product and version plus the protection mode. Attach the relevant sanitized resource status and controller log. If the issue is interoperability related, say which CMP operation and transport are in use.

Never post credentials, private keys, protected CMP messages, full CSRs, production endpoint details or complete Secret resources. Redact endpoint URLs, recipient names and certificate identities when they are sensitive. See [SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so reproduce the problem on the current version before reporting it.
