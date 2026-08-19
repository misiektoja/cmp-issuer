# cmp-issuer

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/cmp-issuer?style=flat-square&color=blue)](https://github.com/misiektoja/cmp-issuer/releases)
[![GitHub Stars](https://img.shields.io/github/stars/misiektoja/cmp-issuer?style=flat-square&color=magenta)](https://github.com/misiektoja/cmp-issuer)
[![Last Commit](https://img.shields.io/github/last-commit/misiektoja/cmp-issuer?style=flat-square&color=green)](https://github.com/misiektoja/cmp-issuer/commits/main)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen?style=flat-square)](https://github.com/misiektoja/cmp-issuer)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml)
[![E2E Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml)
[![Supply chain](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml)

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP)
servers.

Point a cert-manager `Certificate` at a `CMPIssuer` and the certificate is enrolled over CMPv2
and written to the usual TLS Secret, so workloads that already consume cert-manager Secrets need no
change.

CMP message protection is mandatory. HTTP and HTTPS are both supported.

PasswordBasedMac and certificate-signature P10CR have both completed protected cert-manager `Certificate`
enrollments against two independent CMP servers: [Nokia NCM 26.7](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) and [EJBCA Community Edition 9.3.7](https://www.ejbca.org).
Enrollment against EJBCA, over HTTP and over HTTPS, runs on every change in CI.

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

* A [Kubernetes](https://kubernetes.io) cluster, verified on v1.34-1.36
* [cert-manager](https://cert-manager.io/docs/installation/) with external issuer support, verified on
  v1.19-1.21
* [Helm](https://helm.sh/docs/intro/install/) v3
* Kubernetes container runtime like Docker, containerd or CRI-O
* A CMP server, plus its endpoint URL, recipient DN, a credential and the CA certificate that signs its
  CMP responses

## Install

`demo` is the namespace your certificates are issued into. Substitute your own.

```bash
kubectl create namespace demo

helm repo add cmp-issuer https://misiektoja.github.io/cmp-issuer/charts
helm repo update
helm install cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --create-namespace \
  --set 'credentialNamespaces={demo}'
```

That installs the CRDs, the controller and the permission cert-manager needs before it will approve
requests for this issuer type. `credentialNamespaces` lets the controller read the issuer credentials in
`demo` and nowhere else, so name every namespace your issuers live in.

A packaged chart, a self-contained installer manifest and an air-gapped bundle are attached to every
release. Those paths, and the settings this quick start leaves at their defaults, are in
[Installation](https://misiektoja.github.io/cmp-issuer/installation/).

## Issue your first certificate

The short version is below. [Getting started](https://misiektoja.github.io/cmp-issuer/getting-started/) explains each step, shows the
expected output and lists what to check when something does not work.

Store the credential your CMP administrator gave you and the CA certificate that signs the server's CMP
responses:

```bash
kubectl create secret generic cmp-credentials --namespace demo \
  --from-literal=reference='<reference>' \
  --from-literal=secret='<shared-secret>'

kubectl create secret generic cmp-trust --namespace demo \
  --from-file=ca.crt=/path/to/cmp-ca.crt
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

**Observability.** Each completed enrollment writes one `Issued certificate` log line carrying the
subject, serial, validity and issuing CA. The controller also publishes its own Prometheus metrics next
to the controller-runtime and Go defaults, counting enrollments, durations and classified failures per
issuer, with renewals separated from first enrollments. See
[Metrics](https://misiektoja.github.io/cmp-issuer/operations/metrics/).

**Verification.** Every push runs unit, protocol, controller and envtest suites, a Kind-based controller
suite, OpenSSL CMP mock interoperability, Helm chart validation, vulnerability scanning and a credential
scan. Results against real CMP servers are in [Tested PKIs](https://misiektoja.github.io/cmp-issuer/interoperability/tested-pkis/).

## Documentation

Full documentation is at
[misiektoja.github.io/cmp-issuer](https://misiektoja.github.io/cmp-issuer/).

* [Getting started](https://misiektoja.github.io/cmp-issuer/getting-started/)
* [Installation](https://misiektoja.github.io/cmp-issuer/installation/)
* [Support matrix](https://misiektoja.github.io/cmp-issuer/support-matrix/)
* [Enrollment guide](https://misiektoja.github.io/cmp-issuer/guide/enrollment/)
* [Message protection](https://misiektoja.github.io/cmp-issuer/guide/message-protection/)
* [CMPIssuer reference](https://misiektoja.github.io/cmp-issuer/reference/cmpissuer/)
* [Tested PKIs](https://misiektoja.github.io/cmp-issuer/interoperability/tested-pkis/)
* [Metrics](https://misiektoja.github.io/cmp-issuer/operations/metrics/)
* [Troubleshooting](https://misiektoja.github.io/cmp-issuer/operations/troubleshooting/)
* [Known limitations](https://misiektoja.github.io/cmp-issuer/known-limitations/)
* [Threat model](https://misiektoja.github.io/cmp-issuer/security/threat-model/)

## License

Original cmp-issuer code is licensed under Apache-2.0. Dependencies retain their own licenses. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
