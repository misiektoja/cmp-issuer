//go:build e2e
// +build e2e

/*
Copyright 2026 The cmp-issuer Authors.

SPDX-License-Identifier: GPL-3.0-only

This file is part of cmp-issuer.

cmp-issuer is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3.

cmp-issuer is distributed in the hope that it will be useful but WITHOUT ANY
WARRANTY. See the GNU General Public License for more details.
*/

package e2e

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// credentialReaderBinding is the namespace binding that the credential Secret access documentation prescribes.
const credentialReaderBinding = `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cmp-issuer-credential-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cmp-issuer-credential-reader
subjects:
- kind: ServiceAccount
  name: cmp-issuer-controller-manager
  namespace: cmp-issuer-system
`

// certificateTemplate renders a cert-manager Certificate that enrolls through a CMPIssuer.
const certificateTemplate = `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %s
spec:
  secretName: %s
  commonName: %s
  privateKey:
    algorithm: RSA
    size: 2048
    rotationPolicy: Always
  issuerRef:
    name: %s
    kind: CMPIssuer
    group: certmanager.misiektoja.github.io
`

// issuerTemplate renders a CMPIssuer whose pinning block is supplied by the caller.
const issuerTemplate = `apiVersion: certmanager.misiektoja.github.io/v1alpha1
kind: CMPIssuer
metadata:
  name: %s
spec:
  endpoint:
    url: %s
    timeout: 10s
    maxResponseSize: 1048576
  protocol:
    version: 2
    initialEnrollment: P10CR
    recipient: %s
    confirmation: Explicit%s
  protection:
    type: PasswordBasedMac
    passwordBasedMac:
      secretRef:
        name: %s
      referenceKey: reference
      secretKey: secret
      algorithm:
        owf: SHA256
        mac: HMACSHA256
        iterationCount: 1024
  cmpTrust:
    caSecretRef:
      name: %s
      key: ca.crt
  policy:
    grantedModifications: Reject
`

// requestTemplate renders a CertificateRequest submitted directly to an issuer.
const requestTemplate = `apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
  name: %s%s
spec:
  request: %s
  issuerRef:
    name: %s
    kind: CMPIssuer
    group: certmanager.misiektoja.github.io
`

// passwordIssuerManifest renders an issuer protected with PasswordBasedMac, optionally pinning an identifier.
func passwordIssuerManifest(name string, credentialSecret string, trustSecret string, pin string) string {
	pinned := ""
	if pin != "" {
		pinned = "\n    p10crResponseCertReqId: " + pin
	}
	return fmt.Sprintf(issuerTemplate, name, unreachableEndpoint,
		yamlQuote(recipientDN), pinned, credentialSecret, trustSecret)
}

// requestManifest renders a CertificateRequest, optionally carrying a crafted private key annotation.
func requestManifest(name string, issuer string, csrPEM []byte, annotationSecret string) string {
	annotations := ""
	if annotationSecret != "" {
		annotations = fmt.Sprintf("\n  annotations:\n    cert-manager.io/private-key-secret-name: %s", annotationSecret)
	}
	encoded := base64.StdEncoding.EncodeToString(csrPEM)
	return fmt.Sprintf(requestTemplate, name, annotations, encoded, issuer)
}

// secretManifest renders an opaque Secret from decoded entries.
func secretManifest(name string, entries map[string]string) string {
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\ntype: Opaque\ndata:\n", name)
	for key, value := range entries {
		fmt.Fprintf(builder, "  %s: %s\n", key, base64.StdEncoding.EncodeToString([]byte(value)))
	}
	return builder.String()
}

// yamlQuote renders a value as a single quoted YAML scalar so separators inside it stay literal.
func yamlQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
