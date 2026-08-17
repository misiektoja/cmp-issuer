# Getting started

This page takes you from an empty cluster to a certificate issued by your CMP server in six steps.
Every command is meant to be run in order, and each step shows what success looks like so you can tell
where you are.

The example uses PasswordBasedMac protection, which needs only a reference and a secret from your CMP
administrator. Certificate-signature protection is covered in
[Message protection](guide/message-protection.md) once you have the basic flow working.

## What you need

* A Kubernetes cluster and `kubectl`
* [Helm](https://helm.sh/docs/intro/install/) v3
* [cert-manager](https://cert-manager.io/docs/installation/) already installed and running
* A CMP server, and from its administrator:
    * the CMP endpoint URL
    * the recipient distinguished name
    * a PasswordBasedMac reference and secret
    * the CA certificate that signs the server's CMP responses

Throughout this page, `demo` is the namespace your application lives in. Substitute your own.

## Step 1: install cmp-issuer

```bash
helm repo add cmp-issuer https://misiektoja.github.io/cmp-issuer/charts
helm repo update
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --create-namespace
```

This installs the CRDs, the RBAC and the controller. It also grants cert-manager permission to approve
requests for this issuer type, which cert-manager needs before it will act on them at all. Check the
controller is running:

```bash
kubectl -n cmp-issuer-system get pods
```

```text
NAME                                         READY   STATUS    RESTARTS   AGE
cmp-issuer-controller-manager-7d9f8c5b4-x2ktp 1/1     Running   0          30s
```

If cert-manager does not run as the `cert-manager` ServiceAccount in the `cert-manager` namespace,
point the approval permission at it:

```bash
helm upgrade cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --set certManagerApproval.serviceAccountName=<name> \
  --set certManagerApproval.namespace=<namespace>
```

Other installation options, what happens to the CRDs when you uninstall, and how to hand approval to
approver-policy instead are in [Installation](installation.md).

## Step 2: create the namespace and its credentials

```bash
kubectl create namespace demo
```

Store the PasswordBasedMac credential your CMP administrator gave you:

```bash
kubectl create secret generic cmp-credentials \
  --namespace demo \
  --from-literal=reference='<reference>' \
  --from-literal=secret='<shared-secret>'
```

Store the CA certificate that signs your server's CMP responses. This is the CMP trust anchor, and it
is not the same thing as TLS trust:

```bash
kubectl create secret generic cmp-trust \
  --namespace demo \
  --from-file=ca.crt=/path/to/cmp-ca.crt
```

## Step 3: let the controller read those Secrets

The controller has no cluster-wide Secret access. Authorize it for this namespace only:

```bash
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cmp-issuer-credential-reader
  namespace: demo
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cmp-issuer-credential-reader
subjects:
- kind: ServiceAccount
  name: cmp-issuer-controller-manager
  namespace: cmp-issuer-system
EOF
```

Why this boundary exists is explained in [Credential Secret access](operations/secret-access.md).

## Step 4: create the issuer

```bash
kubectl apply -f - <<'EOF'
apiVersion: certmanager.misiektoja.github.io/v1alpha1
kind: CMPIssuer
metadata:
  name: demo-issuer
  namespace: demo
spec:
  endpoint:
    url: http://cmp.example.com:8080/pkix/
  protocol:
    version: 2
    initialEnrollment: P10CR
    recipient: CN=Example CA,O=Example
    confirmation: Explicit
  protection:
    type: PasswordBasedMac
    passwordBasedMac:
      secretRef:
        name: cmp-credentials
  cmpTrust:
    caSecretRef:
      name: cmp-trust
      key: ca.crt
EOF
```

Check that it became ready:

```bash
kubectl get cmpissuers -n demo
```

```text
NAME          READY
demo-issuer   True
```

If it reports `False`, the message names what is missing:

```bash
kubectl describe cmpissuer demo-issuer -n demo
```

A message naming a Secret usually means step 2 or step 3 was skipped or used a different name.

## Step 5: request a certificate

```bash
kubectl apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-tls
  namespace: demo
spec:
  secretName: demo-tls
  commonName: workload.example.com
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    name: demo-issuer
    kind: CMPIssuer
    group: certmanager.misiektoja.github.io
EOF
```

Watch it complete:

```bash
kubectl get certificate demo-tls -n demo
```

```text
NAME       READY   SECRET     AGE
demo-tls   True    demo-tls   12s
```

`READY True` means the CMP exchange finished, the response was authenticated and the certificate was
stored.

## Step 6: look at what you got

```bash
kubectl get secret demo-tls -n demo -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -subject -issuer -dates
```

```text
subject=CN=workload.example.com
issuer=CN=Example CA, O=Example
notBefore=...
notAfter=...
```

The Secret holds `tls.crt` and `tls.key` in the usual cert-manager layout, so any workload that already
consumes a cert-manager Secret can consume this one unchanged.

## If it did not work

| What you see | What it means |
| --- | --- |
| `CertificateRequest` stays pending with no conditions | cert-manager is not permitted to approve these requests, usually because it runs under a different ServiceAccount than step 1 assumed |
| Issuer `Ready False` naming a Secret | Step 2 or 3 was skipped, or a name does not match |
| `Ready False` naming response protection or trust | `cmpTrust` does not hold the CA that signs your server's CMP responses |
| `Ready False` naming the response sender | `recipient` does not name the authority your server answers as |
| Connection refused or timeout | Wrong endpoint URL, or a NetworkPolicy blocks the controller |

Check progress at any time with:

```bash
kubectl get cmptransactions -n demo
kubectl describe certificaterequest -n demo
```

[Troubleshooting](operations/troubleshooting.md) covers these in more detail.

## Where to go next

* [Enrollment](guide/enrollment.md) for the full request lifecycle
* [Message protection](guide/message-protection.md) to move from a shared secret to a bootstrap certificate
* [HTTP and HTTPS transport](guide/transport.md) to move off plain HTTP
* [CMPIssuer reference](reference/cmpissuer.md) for every field
* [Tested PKIs](interoperability/tested-pkis.md) for notes specific to your CMP server
