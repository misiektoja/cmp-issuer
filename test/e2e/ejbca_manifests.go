//go:build e2e
// +build e2e

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
    timeout: 30s
    maxResponseSize: 1048576
  protocol:
    version: 2
    initialEnrollment: P10CR
    recipient: %[3]s
    confirmation: Explicit
  protection:
%[4]s  cmpTrust:
    caSecretRef:
      name: %[5]s
      key: ca.crt
%[6]s  policy:
    grantedModifications: Reject
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
	name        string
	url         string
	recipient   string
	protection  string
	trustSecret string
	transport   string
}

// ejbcaWorkloadManifest renders the CMP server Deployment and the Service that publishes it.
func ejbcaWorkloadManifest(name string, image string, httpPort int, httpsPort int) string {
	return fmt.Sprintf(ejbcaWorkloadTemplate, name, image, httpPort, httpsPort)
}

// ejbcaIssuerManifest renders an issuer for one combination of protection mechanism and transport.
func (issuer ejbcaIssuer) manifest() string {
	return fmt.Sprintf(ejbcaIssuerTemplate, issuer.name, issuer.url, yamlQuote(issuer.recipient),
		issuer.protection, issuer.trustSecret, issuer.transport)
}
