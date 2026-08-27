# cmp-issuer

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/cmp-issuer?style=flat-square&color=blue)](https://github.com/misiektoja/cmp-issuer/releases)
[![GitHub Stars](https://img.shields.io/github/stars/misiektoja/cmp-issuer?style=flat-square&color=magenta)](https://github.com/misiektoja/cmp-issuer)
[![Last Commit](https://img.shields.io/github/last-commit/misiektoja/cmp-issuer?style=flat-square&color=green)](https://github.com/misiektoja/cmp-issuer/commits/main)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen?style=flat-square)](https://github.com/misiektoja/cmp-issuer)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test.yml)
[![E2E Tests](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/test-e2e.yml)
[![Supply chain](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/cmp-issuer/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fcmp-issuer%3Fbadge_cache%3D20260822&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/cmp-issuer)

cmp-issuer is a vendor-neutral cert-manager external issuer for Certificate Management Protocol (CMP)
servers.

Point a cert-manager `Certificate` at a `CMPIssuer` and the certificate is enrolled over CMPv2 with the resulting certificate written to the usual TLS Secret.

CMP message protection is mandatory. HTTP and HTTPS are both supported.

Initial enrollment uses P10CR. A renewal re-enrolls with P10CR by default or uses certificate-authenticated KUR with CRMF proof of possession when the CMP profile requires a true key update.

> This repository is under active initial development. The API group is served at `v1alpha1` and may
> change.

## Contents

* [Prerequisites](#prerequisites)
* [Install](#install)
* [Issue your first certificate](#issue-your-first-certificate)
* [How it works](#how-it-works)
* [Documentation](#documentation)
* [Support](#support)
* [License](#license)

## Prerequisites

* [Kubernetes](https://kubernetes.io) cluster v1.31 or newer, verified on v1.34-1.36
* [cert-manager](https://cert-manager.io/docs/installation/) with external issuer support, verified on
  v1.19-1.21
* [Helm](https://helm.sh/docs/intro/install/) v3
* Kubernetes container runtime like Docker, containerd or CRI-O
* A CMP server (so far tested with [Nokia NCM 26.7](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) and [EJBCA Community Edition 9.3.7](https://www.ejbca.org))

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

`renewal` decides what a cert-manager renewal sends. It defaults to another P10CR enrollment. Set it to
`KUR` when the CMP profile requires a true key update, as described in
[Renewal with P10CR or KUR](https://misiektoja.github.io/cmp-issuer/guide/renewal-and-kur/).

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

**Enrollment.** cert-manager creates the private key and the PKCS #10 request. The controller picks up
the approved `CertificateRequest`, sends the request to your CMP server in a protected P10CR and hands
the issued chain back to cert-manager. `initialEnrollment` accepts only `P10CR` for now.

**Renewal.** A renewal sends another P10CR unless you set `spec.protocol.renewal` to `KUR`.
KUR authenticates the request using the current valid certificate and proves possession of the key that
cert-manager requested. This meets the expectations of CMP profiles requiring a true key update. Renewals
can go to their own CMP alias with `spec.endpoint.renewalUrl`.

**Slow or queued requests.** When the CA cannot issue right away it answers `waiting` and the issuer
polls until the certificate arrives. Every transaction is recorded in a `CMPTransaction` before the
first message goes out, so a controller restart resumes that transaction instead of enrolling a second
time. Follow them with `kubectl get cmptransactions -A`.

**Private keys and secrets.** P10CR never reads workload private keys. KUR reads only the current and
staged keys of the certificate being renewed, after checking the controlling cert-manager `Certificate`,
its owner UID, revision, issuer reference and Secret ownership. The controller reads Secrets only in the
namespaces you name at install time. TLS trust and CMP response trust are configured separately and
every response must come from the authority set as `recipient`.

**CMP server differences.** `spec.protocol.validationProfile` defaults to `Interoperable`, which tolerates
the deviations real CMP servers show. It accepts `certReqId` `-1` or `0` in a P10CR response, echoes the
received value back in `certConf` and treats KUP `caPubs` as untrusted chain candidates rather than
trust anchors. Choose `RFC9483` for the strict checks or pin a single behavior you already know, such as
`spec.protocol.p10crResponseCertReqId`.

**Logs and metrics.** Each completed enrollment writes one `Issued certificate` log line with the
subject, serial, validity and issuing CA. Prometheus metrics count enrollments, durations and classified
failures per issuer, with renewals kept separate from first enrollments. See
[Metrics](https://misiektoja.github.io/cmp-issuer/operations/metrics/).

**Built on cert-manager's own library.** Approval, denial, retry classification, Ready conditions and
Events come from [issuer-lib](https://github.com/cert-manager/issuer-lib), maintained by the
cert-manager project and pinned to an exact version. See
[ADR 0002](https://misiektoja.github.io/cmp-issuer/adr/0002-issuer-lib/).

**Real-world interoperability.** cmp-issuer is tested against real PKI and CMP server implementations to verify that it works beyond synthetic test environments. This includes interoperability testing with EJBCA and Nokia NCM, with results and known compatibility details published in [Tested PKIs](https://misiektoja.github.io/cmp-issuer/interoperability/tested-pkis/).

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
