# cmp-issuer

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP)
servers. Point a cert-manager `Certificate` at a `CMPIssuer` and the certificate is enrolled over CMPv2
and written to the usual TLS Secret, so workloads that already consume cert-manager Secrets need no
change.

CMP message protection is mandatory. HTTP and HTTPS are both supported, and HTTP provides no transport
confidentiality. PasswordBasedMac and certificate-signature P10CR have both completed protected
cert-manager `Certificate` enrollments against two independent CMP servers: Nokia NCM 26.7 and EJBCA Community Edition 9.3.7.

> This repository is under active initial development. The API group is served at `v1alpha1` and may
> change.

## Contents

* [Prerequisites](#prerequisites)
* [Install](#install)
* [Issue your first certificate](#issue-your-first-certificate)
* [How it works](#how-it-works)
* [Documentation](#documentation)
* [License](#license)

## Prerequisites

* A Kubernetes cluster, verified on v1.34
* [cert-manager](https://cert-manager.io/docs/installation/) with external issuer support, verified on
  v1.19 and v1.20
* [Helm](https://helm.sh/docs/intro/install/) v3
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

A packaged chart and a self-contained `install.yaml` are attached to every release. Other install
paths, and what happens to the CRDs on uninstall, are in [Installation](docs/installation.md).

### Let cert-manager approve requests for cmp-issuer

cert-manager's built-in approver approves requests only for issuer types it has explicit permission
for. **Without this, every `CertificateRequest` stays pending with no error and no CMP message is
sent.**

```bash
kubectl apply -f - <<'EOF'
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
EOF
```

## Issue your first certificate

The short version is below. [Getting started](docs/getting-started.md) explains each step, shows the
expected output and lists what to check when something does not work.

Store the credential and the CMP trust anchor, then authorize the controller to read them in that
namespace only:

```bash
kubectl create namespace demo

kubectl create secret generic cmp-credentials --namespace demo \
  --from-literal=reference='<reference>' \
  --from-literal=secret='<shared-secret>'

kubectl create secret generic cmp-trust --namespace demo \
  --from-file=ca.crt=/path/to/cmp-ca.crt

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

Create the issuer:

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

kubectl get cmpissuers -n demo
```

```text
NAME          READY
demo-issuer   True
```

Request a certificate:

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

kubectl get certificate demo-tls -n demo
```

```text
NAME       READY   SECRET     AGE
demo-tls   True    demo-tls   12s
```

## How it works

**Enrollment.** The controller watches approved `CertificateRequest` resources, forwards the signed
PKCS #10 request in a protected P10CR and returns the issued chain to cert-manager. `initialEnrollment`
accepts only `P10CR`, because IR needs CRMF proof of possession over the workload private key, which the
issuer deliberately never reads.

**Asynchronous transactions.** Certificate authorities that queue requests answer with `waiting` instead
of a certificate, and the issuer polls with `pollReq` until the certificate arrives. Each transaction is
recorded in a `CMPTransaction` before the first message is sent, so a controller restart resumes the
existing transaction rather than enrolling a second time. Follow progress with
`kubectl get cmptransactions -A`.

**Security boundaries.** The controller never reads the workload private key. It has no cluster-wide
Secret access, so each namespace hosting a `CMPIssuer` is authorized explicitly. TLS trust and CMP
response trust are configured separately, and every response must be sent by the authority configured
as `recipient`.

**Response compatibility.** The issuer accepts `certReqId` `-1` or `0` in P10CR CP responses, echoes the
received value in `certConf` and rejects anything else. Pin one value with
`spec.protocol.p10crResponseCertReqId` when a server's behavior is known.

**Verification.** Every push runs unit, protocol, controller and envtest suites, a Kind-based controller
suite, OpenSSL CMP mock interoperability, Helm chart validation, vulnerability scanning and a credential
scan. Results against real CMP servers are in [Tested PKIs](docs/interoperability/tested-pkis.md).

## Documentation

Full documentation is in [docs/](docs/).

| Topic | Link |
| --- | --- |
| Getting started | [docs/getting-started.md](docs/getting-started.md) |
| Installation | [docs/installation.md](docs/installation.md) |
| Support matrix | [docs/support-matrix.md](docs/support-matrix.md) |
| Enrollment guide | [docs/guide/enrollment.md](docs/guide/enrollment.md) |
| Message protection | [docs/guide/message-protection.md](docs/guide/message-protection.md) |
| CMPIssuer reference | [docs/reference/cmpissuer.md](docs/reference/cmpissuer.md) |
| Tested PKIs | [docs/interoperability/tested-pkis.md](docs/interoperability/tested-pkis.md) |
| Troubleshooting | [docs/operations/troubleshooting.md](docs/operations/troubleshooting.md) |
| Known limitations | [docs/known-limitations.md](docs/known-limitations.md) |
| Threat model | [docs/security/threat-model.md](docs/security/threat-model.md) |

## License

Original cmp-issuer code is licensed under GPL-3.0-only. Dependencies retain their own licenses. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
