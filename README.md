# cmp-issuer

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/cmp-issuer?style=flat-square&color=blue)](https://github.com/misiektoja/cmp-issuer/releases)
[![GitHub Stars](https://img.shields.io/github/stars/misiektoja/cmp-issuer?style=flat-square&color=magenta)](https://github.com/misiektoja/cmp-issuer)
[![Last Commit](https://img.shields.io/github/last-commit/misiektoja/cmp-issuer?style=flat-square&color=green)](https://github.com/misiektoja/cmp-issuer/commits/main)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen?style=flat-square)](https://github.com/misiektoja/cmp-issuer)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml)
[![E2E Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml)
[![Supply chain](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fcmp-issuer&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/cmp-issuer)

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP)
servers.

Point a cert-manager `Certificate` at a `CMPIssuer` and the certificate is enrolled over CMPv2 with the resulting certificate written to the usual TLS Secret.

CMP message protection is mandatory. HTTP and HTTPS are both supported.

Initial enrollment uses P10CR or IR. Renewal uses P10CR re-enrollment or KUR.

## Contents

* [Prerequisites](#prerequisites)
* [Install](#install)
* [Issue your first certificate](#issue-your-first-certificate)
* [How it works](#how-it-works)
* [Documentation](#documentation)
* [Support](#support)
* [License](#license)

## Prerequisites

* [Kubernetes](https://kubernetes.io) cluster v1.31 or newer, verified on v1.34-1.37
* [cert-manager](https://cert-manager.io/docs/installation/) with external issuer support, verified on
  v1.19-1.21
* [Helm](https://helm.sh/docs/intro/install/) v3
* Kubernetes container runtime like Docker, containerd or CRI-O
* A CMP server (so far tested with [Nokia NCM 26.7](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) and [EJBCA Community Edition 9.3.7](https://www.ejbca.org))

To check from the command line that the CMP server enrolls with your shared secret or certificate
before you configure cert-manager, use [certrally](https://github.com/misiektoja/certrally).

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
    renewal: P10CR
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

cert-manager creates the private key and the CSR. The controller sends each approved `CertificateRequest`
to your CMP server in a protected CMP message and hands the issued chain back to cert-manager.
[Architecture](https://misiektoja.github.io/cmp-issuer/architecture/) shows the components and the
message flow.

* **Restarts** - Every transaction is recorded in a `CMPTransaction` before the first message goes
  out, so a controller restart resumes it instead of enrolling twice. See
  [Transaction recovery](https://misiektoja.github.io/cmp-issuer/guide/transaction-recovery/).
* **Secrets** - The controller reads Secrets only in the namespaces named at install time. P10CR never
  reads workload private keys. IR and KUR read only the keys of the certificate being enrolled or
  renewed. See [Private key handling](https://misiektoja.github.io/cmp-issuer/guide/private-key-handling/).
* **CMP servers** - The default `Interoperable` validation profile tolerates deviations seen on real
  servers and `RFC9483` applies the strict checks. See
  [Tested PKIs](https://misiektoja.github.io/cmp-issuer/interoperability/tested-pkis/).
* **Logs and metrics** - Each enrollment writes one `Issued certificate` log line and Prometheus
  metrics count enrollments, durations and failures per issuer. See
  [Metrics](https://misiektoja.github.io/cmp-issuer/operations/metrics/).

## Documentation

Full documentation is at
[misiektoja.github.io/cmp-issuer](https://misiektoja.github.io/cmp-issuer/).

* [Getting started](https://misiektoja.github.io/cmp-issuer/getting-started/)
* [Installation](https://misiektoja.github.io/cmp-issuer/installation/)
* [Support matrix](https://misiektoja.github.io/cmp-issuer/support-matrix/)
* [Enrollment guide](https://misiektoja.github.io/cmp-issuer/guide/enrollment/)
* [Renewal with P10CR or KUR](https://misiektoja.github.io/cmp-issuer/guide/renewal-and-kur/)
* [Message protection](https://misiektoja.github.io/cmp-issuer/guide/message-protection/)
* [CMPIssuer reference](https://misiektoja.github.io/cmp-issuer/reference/cmpissuer/)
* [Tested PKIs](https://misiektoja.github.io/cmp-issuer/interoperability/tested-pkis/)
* [Metrics](https://misiektoja.github.io/cmp-issuer/operations/metrics/)
* [Troubleshooting](https://misiektoja.github.io/cmp-issuer/operations/troubleshooting/)
* [Known limitations](https://misiektoja.github.io/cmp-issuer/known-limitations/)
* [Threat model](https://misiektoja.github.io/cmp-issuer/security/threat-model/)

## Support

[SUPPORT.md](SUPPORT.md) directs usage questions, bug reports, feature requests and security reports. Check the documentation and gather the sanitized version, resource status and controller log before posting.

## License

Original cmp-issuer code is licensed under Apache-2.0. Dependencies retain their own licenses. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
