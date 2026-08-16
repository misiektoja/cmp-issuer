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

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

const (
	testCMPTrustKey               = "ca.crt"
	testClusterResourceNamespace  = "cluster-resources"
	testIssuerName                = "issuer"
	testIssuerNamespace           = "issuer-ns"
	testPasswordReferenceKey      = "reference"
	testUnrelatedPrivateKeySecret = "unrelated-private-key"
)

// recordingClient records object names read through Get.
type recordingClient struct {
	client.Client
	mu   sync.Mutex
	gets []types.NamespacedName
}

// Get records a read before delegating to the fake Kubernetes client.
func (c *recordingClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	c.mu.Lock()
	c.gets = append(c.gets, key)
	c.mu.Unlock()
	return c.Client.Get(ctx, key, object, options...)
}

// readNames returns a snapshot of recorded reads.
func (c *recordingClient) readNames() []types.NamespacedName {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]types.NamespacedName(nil), c.gets...)
}

// fakeProtocolClient returns a configured chain and records enrollment calls.
type fakeProtocolClient struct {
	mu      sync.Mutex
	calls   int
	request protocol.EnrollmentRequest
	result  protocol.EnrollmentResult
	err     error
}

// EnrollP10CR records the request and returns the configured result.
func (c *fakeProtocolClient) EnrollP10CR(_ context.Context, request protocol.EnrollmentRequest) (protocol.EnrollmentResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.request = request
	return c.result, c.err
}

// fakeCertificateRequest implements issuer-lib's request contract for signer unit tests.
type fakeCertificateRequest struct {
	metav1.ObjectMeta
	details issuersigner.CertificateDetails
}

// GetCertificateDetails returns the configured signed CSR.
func (r *fakeCertificateRequest) GetCertificateDetails() (issuersigner.CertificateDetails, error) {
	return r.details, nil
}

// GetConditions returns no synthetic request conditions.
func (r *fakeCertificateRequest) GetConditions() []metav1.Condition { return nil }

// testCertificateMaterial creates a root certificate, PEM bundle and PKCS #8 private key.
func testCertificateMaterial(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

// testCSR creates a PEM-encoded signed PKCS #10 request.
func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "workload"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
}

// validSpec returns a fully explicit P10CR PasswordBasedMac issuer spec.
func validSpec(endpoint string) cmpv1alpha1.CMPIssuerSpec {
	return cmpv1alpha1.CMPIssuerSpec{Endpoint: cmpv1alpha1.EndpointSpec{URL: endpoint, Timeout: metav1.Duration{Duration: 30 * time.Second}, MaxResponseSize: 1 << 20}, Protocol: cmpv1alpha1.ProtocolSpec{Version: 2, InitialEnrollment: cmpv1alpha1.InitialEnrollmentP10CR, Recipient: "C=DE, O=Test, CN=Test CA", Confirmation: "Explicit"}, Protection: cmpv1alpha1.ProtectionSpec{Type: cmpv1alpha1.ProtectionTypePasswordBasedMac, PasswordBasedMac: &cmpv1alpha1.PasswordBasedMacSpec{SecretRef: cmpv1alpha1.LocalSecretReference{Name: "cmp-auth"}, ReferenceKey: testPasswordReferenceKey, SecretKey: "secret", Algorithm: cmpv1alpha1.PasswordBasedMacAlgorithmSpec{OWF: "SHA256", MAC: "HMACSHA256", IterationCount: 1024}}}, CMPTrust: cmpv1alpha1.CMPTrustSpec{CASecretRef: cmpv1alpha1.SecretKeyReference{Name: "cmp-trust", Key: testCMPTrustKey}}, Transaction: cmpv1alpha1.TransactionSpec{MaximumDuration: metav1.Duration{Duration: 10 * time.Minute}, MinimumPollInterval: metav1.Duration{Duration: time.Second}, MaximumPollInterval: metav1.Duration{Duration: time.Minute}, MaximumPolls: 60}, Policy: cmpv1alpha1.PolicySpec{GrantedModifications: cmpv1alpha1.GrantedModificationsReject}}
}

// testScheme creates a scheme containing core and cmp-issuer APIs.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cmpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// credentialSecrets returns valid PasswordBasedMac and CMP trust Secrets.
func credentialSecrets(t *testing.T, namespace string) (*corev1.Secret, *corev1.Secret, *x509.Certificate) {
	t.Helper()
	certificate, _, certificatePEM, _ := testCertificateMaterial(t, "CMP Root")
	auth := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cmp-auth", Namespace: namespace}, Data: map[string][]byte{testPasswordReferenceKey: []byte("test-reference"), "secret": []byte("test-shared-secret")}}
	trust := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cmp-trust", Namespace: namespace}, Data: map[string][]byte{testCMPTrustKey: certificatePEM}}
	return auth, trust, certificate
}

// TestValidateSpec covers independent local validation branches.
func TestValidateSpec(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*cmpv1alpha1.CMPIssuerSpec)
	}{
		{name: "relative endpoint", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Endpoint.URL = "/cmp" }},
		{name: "endpoint credentials", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Endpoint.URL = "https://user@example.test/cmp" }},
		{name: "unsupported operation", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Protocol.InitialEnrollment = "IR" }},
		{name: "unsupported P10CR response certReqId", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			unsupported := int64(1)
			spec.Protocol.P10CRResponseCertReqID = &unsupported
		}},
		{name: "profile not encoded", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Protocol.CertProfile = "profile" }},
		{name: "same password key", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			spec.Protection.PasswordBasedMac.SecretKey = testPasswordReferenceKey
		}},
		{name: "unsupported algorithm", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Protection.PasswordBasedMac.Algorithm.OWF = "SHA1" }},
		{name: "both protection modes", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			spec.Protection.Signature = &cmpv1alpha1.SignatureProtectionSpec{}
		}},
		{name: "mTLS reserved", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			spec.Transport.TLS = &cmpv1alpha1.TLSTransportSpec{ClientCertificateSecretRef: &cmpv1alpha1.LocalSecretReference{Name: "mtls"}}
		}},
		{name: "TLS trust on HTTP", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			spec.Endpoint.URL = "http://example.test/cmp"
			spec.Transport.TLS = &cmpv1alpha1.TLSTransportSpec{CASecretRef: &cmpv1alpha1.SecretKeyReference{Name: "tls", Key: testCMPTrustKey}}
		}},
		{name: "poll interval order", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			spec.Transaction.MaximumPollInterval.Duration = time.Millisecond
		}},
		{name: "unknown modification policy", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Policy.GrantedModifications = "Unknown" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := validSpec("https://example.test/cmp")
			test.mutate(&spec)
			if _, err := validateSpec(&spec); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

// TestCheckUsesIssuerCredentialNamespace verifies Secret references cannot select another namespace.
func TestCheckUsesIssuerCredentialNamespace(t *testing.T) {
	auth, trust, _ := credentialSecrets(t, "other")
	kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust).Build()
	signer := &Signer{KubeClient: kubeClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace}
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: "allowed"}, Spec: validSpec("https://example.test/cmp")}
	err := signer.Check(context.Background(), issuer)
	var configurationErr *configurationError
	if !errors.As(err, &configurationErr) || configurationErr.Permanent {
		t.Fatalf("expected retryable namespace-scoped Secret failure, got %v", err)
	}
}

// TestCheckAllowsHTTPAndEmitsWarning verifies HTTP is Ready-capable with one clear event.
func TestCheckAllowsHTTPAndEmitsWarning(t *testing.T) {
	auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
	kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust).Build()
	recorder := events.NewFakeRecorder(10)
	signer := &Signer{KubeClient: kubeClient, EventRecorder: recorder, ClusterResourceNamespace: testClusterResourceNamespace}
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace, Generation: 1}, Spec: validSpec("http://example.test/cmp")}
	if err := signer.Check(context.Background(), issuer); err != nil {
		t.Fatalf("HTTP issuer check failed: %v", err)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "transport confidentiality is absent") {
			t.Fatalf("unexpected warning event: %s", event)
		}
	case <-time.After(time.Second):
		t.Fatal("expected HTTP confidentiality warning event")
	}
}

// TestSignIgnoresPrivateKeySecretAnnotation verifies P10CR reads only configured credential Secrets.
func TestSignIgnoresPrivateKeySecretAnnotation(t *testing.T) {
	auth, trust, leaf := credentialSecrets(t, testIssuerNamespace)
	unrelated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testUnrelatedPrivateKeySecret, Namespace: testIssuerNamespace}, Data: map[string][]byte{"tls.key": []byte("sensitive")}}
	baseClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, unrelated).Build()
	recording := &recordingClient{Client: baseClient}
	protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{leaf}}}
	signer := &Signer{KubeClient: recording, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace}
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: validSpec("https://example.test/cmp")}
	legacyCertReqID := cmpv1alpha1.P10CRResponseCertReqIDLegacyZero
	issuer.Spec.Protocol.P10CRResponseCertReqID = &legacyCertReqID
	request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: "request", Namespace: testIssuerNamespace, Annotations: map[string]string{"cert-manager.io/private-key-secret-name": testUnrelatedPrivateKeySecret}}, details: issuersigner.CertificateDetails{CSR: testCSR(t)}}
	bundle, err := signer.Sign(context.Background(), request, issuer)
	if err != nil || len(bundle.ChainPEM) == 0 {
		t.Fatalf("Sign failed: %v", err)
	}
	for _, read := range recording.readNames() {
		if read.Name == testUnrelatedPrivateKeySecret {
			t.Fatal("signer read the annotated private-key Secret")
		}
	}
	if protocolClient.calls != 1 {
		t.Fatalf("expected one protocol call, got %d", protocolClient.calls)
	}
	if protocolClient.request.ResponseCertReqID != cmpv1alpha1.P10CRResponseCertReqIDLegacyZero {
		t.Fatalf("expected legacy response certReqId, got %d", protocolClient.request.ResponseCertReqID)
	}
}
