//go:build e2e

/*
Copyright 2026 The cmp-issuer Authors.

SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import "fmt"

// ejbcaWorkloadTemplate renders the CMP server that the enrollment specs enroll from.
//
// The image already carries its certification authority, its CMP aliases and its TLS keystore, so the
// container only has to start. The readiness probe is the health check of the application itself, which
// answers once the deployment has finished and the database is open.
const ejbcaWorkloadTemplate = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  labels:
    app: %[1]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      containers:
      - name: ejbca
        image: %[2]s
        imagePullPolicy: IfNotPresent
        ports:
        - name: http
          containerPort: %[3]d
        - name: https
          containerPort: %[4]d
        readinessProbe:
          httpGet:
            path: /ejbca/publicweb/healthcheck/ejbcahealth
            port: http
          initialDelaySeconds: 20
          periodSeconds: 5
          failureThreshold: 90
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
spec:
  selector:
    app: %[1]s
  ports:
  - name: http
    port: %[3]d
    targetPort: http
  - name: https
    port: %[4]d
    targetPort: https
`

// ejbcaIssuerTemplate renders a CMPIssuer whose protection and transport blocks are supplied by the caller.
const ejbcaIssuerTemplate = `apiVersion: certmanager.misiektoja.github.io/v1alpha1
kind: CMPIssuer
metadata:
  name: %[1]s
spec:
  endpoint:
    url: %[2]s
%[8]s    timeout: 30s
    maxResponseSize: 1048576
  protocol:
    version: 2
    initialEnrollment: %[9]s
%[7]s    recipient: %[3]s
    confirmation: Explicit
  protection:
%[4]s  cmpTrust:
    caSecretRef:
      name: %[5]s
      key: ca.crt
%[6]s  policy:
    grantedModifications: Reject
`

// ejbcaKURCertificateTemplate renders a client-mode certificate with selectable key rotation.
const ejbcaKURCertificateTemplate = `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %[1]s
spec:
  secretName: %[1]s-tls
  commonName: %[1]s
  duration: 2160h
  revisionHistoryLimit: 2
  privateKey:
    algorithm: RSA
    size: 2048
    rotationPolicy: %[2]s
  issuerRef:
    name: %[3]s
    kind: CMPIssuer
    group: certmanager.misiektoja.github.io
`

// passwordBasedMacProtection renders the protection block of a request protected with a shared secret.
const passwordBasedMacProtection = `    type: PasswordBasedMac
    passwordBasedMac:
      secretRef:
        name: %s
      referenceKey: reference
      secretKey: secret
      algorithm:
        owf: SHA256
        mac: HMACSHA256
        iterationCount: 1024
`

// signatureProtection renders the protection block of a request protected with a certificate signature.
const signatureProtection = `    type: Signature
    signature:
      secretRef:
        name: %s
      certificateKey: tls.crt
      privateKeyKey: tls.key
`

// tlsTransport renders the transport block that pins the authority of the endpoint TLS certificate.
const tlsTransport = `  transport:
    tls:
      caSecretRef:
        name: %s
        key: ca.crt
`

// ejbcaIssuer describes one combination of endpoint, protection mechanism and transport.
type ejbcaIssuer struct {
	name              string
	url               string
	recipient         string
	protection        string
	trustSecret       string
	transport         string
	initialEnrollment string
	renewal           string
	renewalURL        string
	validationProfile string
	kurResponseCAPubs string
	requestedValidity string
	renewalFallback   string
	proofOfPossession string
}

// ejbcaWorkloadManifest renders the CMP server Deployment and the Service that publishes it.
func ejbcaWorkloadManifest(name string, image string, httpPort int, httpsPort int) string {
	return fmt.Sprintf(ejbcaWorkloadTemplate, name, image, httpPort, httpsPort)
}

// ejbcaIssuerManifest renders an issuer for one combination of protection mechanism and transport.
func (issuer ejbcaIssuer) manifest() string {
	renewal := ""
	if issuer.renewal != "" {
		renewal = "    renewal: " + issuer.renewal + "\n"
	}
	if issuer.validationProfile != "" {
		renewal += "    validationProfile: " + issuer.validationProfile + "\n"
	}
	if issuer.kurResponseCAPubs != "" {
		renewal += "    kurResponseCaPubs: " + issuer.kurResponseCAPubs + "\n"
	}
	if issuer.requestedValidity != "" {
		renewal += "    requestedValidity: " + issuer.requestedValidity + "\n"
	}
	if issuer.renewalFallback != "" {
		renewal += "    renewalFallback: " + issuer.renewalFallback + "\n"
	}
	if issuer.proofOfPossession != "" {
		renewal += "    proofOfPossession: " + issuer.proofOfPossession + "\n"
	}
	initialEnrollment := issuer.initialEnrollment
	if initialEnrollment == "" {
		initialEnrollment = operationP10CR
	}
	renewalURL := ""
	if issuer.renewalURL != "" {
		renewalURL = "    renewalUrl: " + issuer.renewalURL + "\n"
	}
	return fmt.Sprintf(ejbcaIssuerTemplate, issuer.name, issuer.url, yamlQuote(issuer.recipient),
		issuer.protection, issuer.trustSecret, issuer.transport, renewal, renewalURL, initialEnrollment)
}

// ejbcaKURCertificateManifest renders one certificate used for a two-revision client-mode update.
func ejbcaKURCertificateManifest(name string, rotationPolicy string, issuer string) string {
	return fmt.Sprintf(ejbcaKURCertificateTemplate, name, rotationPolicy, issuer)
}

// mtlsPKITemplate renders the authority, server certificate and client certificate of the HTTPS proxy
// that requires a TLS client certificate. cert-manager issues all three, so the client certificate
// Secret has exactly the layout a user gets from a cert-manager Certificate.
const mtlsPKITemplate = `apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: %[1]s-root
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %[1]s
spec:
  isCA: true
  commonName: cmp-issuer e2e mTLS authority
  secretName: %[1]s
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: %[1]s-root
    kind: Issuer
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: %[1]s
spec:
  ca:
    secretName: %[1]s
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %[2]s
spec:
  secretName: %[2]s
  dnsNames:
  - %[4]s
  usages:
  - server auth
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: %[1]s
    kind: Issuer
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %[3]s
spec:
  secretName: %[3]s
  commonName: %[5]s
  usages:
  - client auth
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: %[1]s
    kind: Issuer
`

// mtlsProxyTemplate renders an HTTPS proxy in front of the CMP server's HTTP port that refuses every
// client without a certificate from the mTLS authority. Its access log records the verification result
// and the client subject of each request, which is how a spec sees the certificate that was presented.
const mtlsProxyTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: %[1]s
data:
  default.conf: |
    log_format mtls '$ssl_client_verify "$ssl_client_s_dn" "$request" $status';
    server {
      listen %[3]d ssl;
      ssl_certificate /etc/nginx/tls/tls.crt;
      ssl_certificate_key /etc/nginx/tls/tls.key;
      ssl_client_certificate /etc/nginx/tls/ca.crt;
      ssl_verify_client on;
      access_log /var/log/nginx/access.log mtls;
      location / {
        proxy_pass %[4]s;
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  labels:
    app: %[1]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      containers:
      - name: proxy
        image: %[2]s
        imagePullPolicy: IfNotPresent
        ports:
        - name: https
          containerPort: %[3]d
        readinessProbe:
          tcpSocket:
            port: https
          periodSeconds: 2
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: config
          mountPath: /etc/nginx/conf.d
          readOnly: true
        - name: tls
          mountPath: /etc/nginx/tls
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: %[1]s
      - name: tls
        secret:
          secretName: %[5]s
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
spec:
  selector:
    app: %[1]s
  ports:
  - name: https
    port: %[3]d
    targetPort: https
`

// mtlsTransport renders the transport block that trusts the proxy authority and presents a client certificate.
const mtlsTransport = `  transport:
    tls:
      caSecretRef:
        name: %s
        key: ca.crt
      clientCertificateSecretRef:
        name: %s
`

// mtlsPKIManifest renders the cert-manager resources of the mTLS proxy and its client.
func mtlsPKIManifest(authority string, serverSecret string, clientSecret string, hostname string, clientCommonName string) string {
	return fmt.Sprintf(mtlsPKITemplate, authority, serverSecret, clientSecret, hostname, clientCommonName)
}

// mtlsProxyManifest renders the HTTPS proxy that requires a client certificate in front of upstream.
func mtlsProxyManifest(name string, image string, port int, upstream string, serverSecret string) string {
	return fmt.Sprintf(mtlsProxyTemplate, name, image, port, upstream, serverSecret)
}
