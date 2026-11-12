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

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
)

const (
	testTLSClientSecretName = "cmp-tls-client"
	testHTTPEndpointURL     = "http://example.test/cmp"
)

// testTLSClientMaterial issues a TLS client leaf under a fresh root and returns the leaf, the root
// and the tls.crt and tls.key values, with the root following the leaf in tls.crt.
func testTLSClientMaterial(t *testing.T) (*x509.Certificate, *x509.Certificate, []byte, []byte) {
	t.Helper()
	root, rootKey, rootPEM := testCertificateMaterial(t, "TLS Client Root")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "cmp-issuer TLS client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: pemCertificateBlockType, Bytes: leafDER}), rootPEM...)
	return leaf, root, chainPEM, testKURKeyPEM(t, key)
}

// tlsClientSpec returns an HTTPS issuer spec that references the TLS client certificate Secret.
func tlsClientSpec() cmpv1alpha1.CMPIssuerSpec {
	spec := validSpec("https://example.test/cmp")
	spec.Transport.TLS = &cmpv1alpha1.TLSTransportSpec{ClientCertificateSecretRef: &cmpv1alpha1.LocalSecretReference{Name: testTLSClientSecretName}}
	return spec
}

// TestValidateSpecAllowsTLSClientCertificate verifies a client certificate is accepted when the
// enrollment or the renewal endpoint uses HTTPS.
func TestValidateSpecAllowsTLSClientCertificate(t *testing.T) {
	for _, test := range []struct {
		name       string
		endpoint   string
		renewalURL string
	}{
		{name: "HTTPS endpoint", endpoint: "https://example.test/cmp"},
		{name: "HTTPS renewal endpoint", endpoint: testHTTPEndpointURL, renewalURL: testRenewalURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := tlsClientSpec()
			spec.Endpoint.URL = test.endpoint
			spec.Endpoint.RenewalURL = test.renewalURL
			if test.renewalURL != "" {
				spec.Protocol.InitialEnrollment = cmpv1alpha1.InitialEnrollmentIR
				spec.Protocol.Renewal = cmpv1alpha1.RenewalKUR
			}
			if _, err := validateSpec(&spec); err != nil {
				t.Fatalf("validate TLS client certificate: %v", err)
			}
		})
	}
}

// TestLoadTLSClientCertificate verifies the Secret's chain and key reach the enrollment request and
// that the Secret is part of the transaction configuration, so rotating it is detected.
func TestLoadTLSClientCertificate(t *testing.T) {
	auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
	leaf, root, chainPEM, keyPEM := testTLSClientMaterial(t)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testTLSClientSecretName, Namespace: testIssuerNamespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: chainPEM, corev1.TLSPrivateKeyKey: keyPEM}}
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: tlsClientSpec()}
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, secret).Build()
	signer := &Signer{KubeClient: kube, ClusterResourceNamespace: testClusterResourceNamespace}
	configuration, err := signer.loadRuntimeConfiguration(context.Background(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	certificate := configuration.EnrollmentRequest.TLSClientCertificate
	if certificate == nil || len(certificate.Certificate) != 2 || !certificate.Leaf.Equal(leaf) {
		t.Fatal("expected the client leaf followed by its issuer")
	}
	if issued, err := x509.ParseCertificate(certificate.Certificate[1]); err != nil || !issued.Equal(root) {
		t.Fatalf("expected the issuer certificate after the leaf, got %v", err)
	}
	if _, exists := configuration.ConfigurationSecrets[types.NamespacedName{Namespace: testIssuerNamespace, Name: secret.Name}]; !exists {
		t.Fatal("TLS client Secret is missing from the transaction configuration")
	}
}

// TestLoadTLSClientCertificateIgnoredWithoutHTTPS verifies an HTTP-only issuer never reads the Secret.
func TestLoadTLSClientCertificateIgnoredWithoutHTTPS(t *testing.T) {
	spec := tlsClientSpec()
	getSecret := func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError) {
		t.Fatal("the TLS client Secret was read for an HTTP endpoint")
		return nil, nil
	}
	if certificate, err := loadTLSClientCertificate(getSecret, &spec, false); certificate != nil || err != nil {
		t.Fatalf("expected no client certificate, got %v", err)
	}
}

// TestLoadTLSClientCertificateRejectsInvalidSecrets verifies incomplete or mismatched Secrets keep
// the issuer from enrolling and are retried, so fixing the Secret recovers the issuer.
func TestLoadTLSClientCertificateRejectsInvalidSecrets(t *testing.T) {
	_, _, chainPEM, keyPEM := testTLSClientMaterial(t)
	_, _, _, otherKeyPEM := testTLSClientMaterial(t)
	for _, test := range []struct {
		name string
		data map[string][]byte
	}{
		{name: "missing certificate", data: map[string][]byte{corev1.TLSPrivateKeyKey: keyPEM}},
		{name: "missing key", data: map[string][]byte{corev1.TLSCertKey: chainPEM}},
		{name: "invalid certificate", data: map[string][]byte{corev1.TLSCertKey: []byte("invalid certificate"), corev1.TLSPrivateKeyKey: keyPEM}},
		{name: "invalid key", data: map[string][]byte{corev1.TLSCertKey: chainPEM, corev1.TLSPrivateKeyKey: []byte("invalid key")}},
		{name: "key of another certificate", data: map[string][]byte{corev1.TLSCertKey: chainPEM, corev1.TLSPrivateKeyKey: otherKeyPEM}},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := tlsClientSpec()
			getSecret := func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError) {
				return &corev1.Secret{Data: test.data}, nil
			}
			certificate, err := loadTLSClientCertificate(getSecret, &spec, true)
			if certificate != nil || err == nil || err.Permanent {
				t.Fatalf("expected a retryable configuration failure, got %v", err)
			}
		})
	}
	t.Run("missing Secret", func(t *testing.T) {
		auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
		issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: tlsClientSpec()}
		kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust).Build()
		signer := &Signer{KubeClient: kube, ClusterResourceNamespace: testClusterResourceNamespace}
		if _, err := signer.loadRuntimeConfiguration(context.Background(), issuer); err == nil || err.Permanent {
			t.Fatalf("expected a retryable configuration failure, got %v", err)
		}
	})
}
