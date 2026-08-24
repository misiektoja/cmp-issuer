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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	testAuthSecretName            = "cmp-auth"
	testClusterResourceNamespace  = "cluster-resources"
	testIssuerName                = "issuer"
	testIssuerNamespace           = "issuer-ns"
	testPasswordReferenceKey      = "reference"
	testTrustSecretName           = "cmp-trust"
	testUnrelatedPrivateKeySecret = "unrelated-private-key"
	testWorkloadCommonName        = "workload"
	testHTTPExchangeOperation     = "HTTP exchange"
	testFailureSystemUnavailable  = "systemUnavail"
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
	mu             sync.Mutex
	calls          int
	kurCalls       int
	polls          int
	confirms       int
	request        protocol.EnrollmentRequest
	pollRequest    protocol.PollRequest
	confirmRequest protocol.ConfirmRequest
	result         protocol.EnrollmentResult
	err            error
	queue          []fakeExchange
}

// EnrollP10CR records the enrollment request and returns the configured result.
func (c *fakeProtocolClient) EnrollP10CR(_ context.Context, request protocol.EnrollmentRequest) (protocol.EnrollmentResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.request = request
	return c.next()
}

// EnrollKUR records the key update request and returns the configured result.
func (c *fakeProtocolClient) EnrollKUR(_ context.Context, request protocol.EnrollmentRequest) (protocol.EnrollmentResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kurCalls++
	c.request = request
	return c.next()
}

// PollP10CR records the poll request and returns the configured result.
func (c *fakeProtocolClient) PollP10CR(_ context.Context, poll protocol.PollRequest) (protocol.EnrollmentResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.polls++
	c.pollRequest = poll
	return c.next()
}

// ConfirmP10CR records the confirmation request and returns the configured result.
func (c *fakeProtocolClient) ConfirmP10CR(_ context.Context, confirm protocol.ConfirmRequest) (protocol.EnrollmentResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.confirms++
	c.confirmRequest = confirm
	return c.next()
}

// next returns the head of the queued exchanges, or the single configured outcome when it is empty.
func (c *fakeProtocolClient) next() (protocol.EnrollmentResult, error) {
	if len(c.queue) == 0 {
		return c.result, c.err
	}
	exchange := c.queue[0]
	c.queue = c.queue[1:]
	return exchange.result, exchange.err
}

// fakeExchange is one queued protocol outcome for a multi-step transaction test.
type fakeExchange struct {
	result protocol.EnrollmentResult
	err    error
}

// testTransactions returns a transaction store backed by one fake Kubernetes client.
func testTransactions(kubeClient client.Client) *transactionStore {
	return &transactionStore{reader: kubeClient, writer: kubeClient}
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
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: pemCertificateBlockType, Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

// testCSR creates a PEM-encoded signed PKCS #10 request.
func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testWorkloadCommonName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
}

// validSpec returns a fully explicit P10CR PasswordBasedMac issuer spec.
func validSpec(endpoint string) cmpv1alpha1.CMPIssuerSpec {
	return cmpv1alpha1.CMPIssuerSpec{Endpoint: cmpv1alpha1.EndpointSpec{URL: endpoint, Timeout: metav1.Duration{Duration: 30 * time.Second}, MaxResponseSize: 1 << 20}, Protocol: cmpv1alpha1.ProtocolSpec{Version: 2, InitialEnrollment: cmpv1alpha1.InitialEnrollmentP10CR, Recipient: "C=DE, O=Test, CN=Test CA", Confirmation: "Explicit"}, Protection: cmpv1alpha1.ProtectionSpec{Type: cmpv1alpha1.ProtectionTypePasswordBasedMac, PasswordBasedMac: &cmpv1alpha1.PasswordBasedMacSpec{SecretRef: cmpv1alpha1.LocalSecretReference{Name: testAuthSecretName}, ReferenceKey: testPasswordReferenceKey, SecretKey: "secret", Algorithm: cmpv1alpha1.PasswordBasedMacAlgorithmSpec{OWF: "SHA256", MAC: "HMACSHA256", IterationCount: 1024}}}, CMPTrust: cmpv1alpha1.CMPTrustSpec{CASecretRef: cmpv1alpha1.SecretKeyReference{Name: testTrustSecretName, Key: testCMPTrustKey}}, Transaction: cmpv1alpha1.TransactionSpec{MaximumDuration: metav1.Duration{Duration: 10 * time.Minute}, MinimumPollInterval: metav1.Duration{Duration: time.Second}, MaximumPollInterval: metav1.Duration{Duration: time.Minute}, MaximumPolls: 60}, Policy: cmpv1alpha1.PolicySpec{GrantedModifications: cmpv1alpha1.GrantedModificationsReject}}
}

// testScheme creates a scheme containing core and cmp-issuer APIs.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := certmanagerv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cmpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// testKURKeyPEM encodes one private key for a cert-manager TLS Secret.
func testKURKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

// testKURCertificate issues a currently valid leaf for the selected workload key and identity.
func testKURCertificate(t *testing.T, key *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: testWorkloadCommonName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: pemCertificateBlockType, Bytes: certificateDER})
}

// testKURRequestObjects builds the cert-manager ownership chain and current and staged key Secrets.
func testKURRequestObjects(t *testing.T, issuer *cmpv1alpha1.CMPIssuer, rotateKey bool) (*fakeCertificateRequest, *certmanagerv1.Certificate, *corev1.Secret, *corev1.Secret) {
	t.Helper()
	currentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestedKey := currentKey
	if rotateKey {
		requestedKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testWorkloadCommonName}}, requestedKey)
	if err != nil {
		t.Fatal(err)
	}
	_, currentCertificatePEM := testKURCertificate(t, currentKey)
	revision := 1
	nextPrivateKeySecretName := "workload-next-key"
	certificate := &certmanagerv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: testWorkloadCommonName, Namespace: testIssuerNamespace, UID: types.UID("22222222-2222-2222-2222-222222222222")}, Spec: certmanagerv1.CertificateSpec{SecretName: "workload-tls", IssuerRef: cmmeta.IssuerReference{Name: issuer.Name, Kind: cmpv1alpha1.TransactionIssuerKindNamespaced, Group: cmpv1alpha1.GroupVersion.Group}}, Status: certmanagerv1.CertificateStatus{Revision: &revision, NextPrivateKeySecretName: &nextPrivateKeySecretName}}
	controllerReference := *metav1.NewControllerRef(certificate, certmanagerv1.SchemeGroupVersion.WithKind("Certificate"))
	currentSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: certificate.Spec.SecretName, Namespace: testIssuerNamespace}, Data: map[string][]byte{corev1.TLSCertKey: currentCertificatePEM, corev1.TLSPrivateKeyKey: testKURKeyPEM(t, currentKey)}}
	stagedSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: nextPrivateKeySecretName, Namespace: testIssuerNamespace, Labels: map[string]string{certmanagerv1.IsNextPrivateKeySecretLabelKey: "true"}, OwnerReferences: []metav1.OwnerReference{controllerReference}}, Data: map[string][]byte{corev1.TLSPrivateKeyKey: testKURKeyPEM(t, requestedKey)}}
	request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testIssuerNamespace, UID: testRequestUID, Annotations: map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "2", certmanagerv1.CertificateRequestPrivateKeyAnnotationKey: nextPrivateKeySecretName}, OwnerReferences: []metav1.OwnerReference{controllerReference}}, details: issuersigner.CertificateDetails{CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})}}
	return request, certificate, currentSecret, stagedSecret
}

// credentialSecrets returns valid PasswordBasedMac and CMP trust Secrets.
func credentialSecrets(t *testing.T, namespace string) (*corev1.Secret, *corev1.Secret, *x509.Certificate) {
	t.Helper()
	certificate, _, certificatePEM, _ := testCertificateMaterial(t, "CMP Root")
	auth := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testAuthSecretName, Namespace: namespace}, Data: map[string][]byte{testPasswordReferenceKey: []byte("test-reference"), "secret": []byte("test-shared-secret")}}
	trust := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testTrustSecretName, Namespace: namespace}, Data: map[string][]byte{testCMPTrustKey: certificatePEM}}
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
		{name: "relative renewal endpoint", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Endpoint.RenewalURL = "/keyupdate" }},
		{name: "unsupported operation", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) { spec.Protocol.InitialEnrollment = "IR" }},
		{name: "unsupported P10CR response certReqId", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			unsupported := int64(1)
			spec.Protocol.P10CRResponseCertReqID = &unsupported
		}},
		{name: "unsupported MAC response protection", mutate: func(spec *cmpv1alpha1.CMPIssuerSpec) {
			spec.Protocol.MACResponseProtection = "Any"
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

// TestValidateSpecAllowsOmittedOptionalObjects verifies optional parent objects use their safe defaults.
func TestValidateSpecAllowsOmittedOptionalObjects(t *testing.T) {
	spec := validSpec("https://example.test/cmp")
	spec.Transaction = cmpv1alpha1.TransactionSpec{}
	spec.Policy = cmpv1alpha1.PolicySpec{}
	if _, err := validateSpec(&spec); err != nil {
		t.Fatalf("validate omitted optional objects: %v", err)
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
	baseClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, unrelated).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
	recording := &recordingClient{Client: baseClient}
	protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{leaf}}}
	signer := &Signer{KubeClient: recording, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(baseClient)}
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
	if protocolClient.request.ResponseCertReqID == nil || *protocolClient.request.ResponseCertReqID != cmpv1alpha1.P10CRResponseCertReqIDLegacyZero {
		t.Fatalf("expected pinned legacy response certReqId, got %v", protocolClient.request.ResponseCertReqID)
	}
}

// TestSignLeavesResponseCertReqIDUnpinnedByDefault verifies an omitted issuer field forwards no pinned identifier.
func TestSignLeavesResponseCertReqIDUnpinnedByDefault(t *testing.T) {
	auth, trust, leaf := credentialSecrets(t, testIssuerNamespace)
	kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
	protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{leaf}}}
	signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: validSpec("https://example.test/cmp")}
	request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: "request", Namespace: testIssuerNamespace}, details: issuersigner.CertificateDetails{CSR: testCSR(t)}}
	if _, err := signer.Sign(context.Background(), request, issuer); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if protocolClient.request.ResponseCertReqID != nil {
		t.Fatalf("expected no pinned response certReqId, got %d", *protocolClient.request.ResponseCertReqID)
	}
}

// TestSignForwardsMACResponseProtection verifies only an explicit Strict tightens MAC response protection.
func TestSignForwardsMACResponseProtection(t *testing.T) {
	tests := []struct {
		name      string
		configure string
		allowed   bool
	}{
		{name: "unset", configure: "", allowed: true},
		{name: "strict", configure: cmpv1alpha1.MACResponseProtectionStrict, allowed: false},
		{name: "allow signature", configure: cmpv1alpha1.MACResponseProtectionAllowSignature, allowed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth, trust, leaf := credentialSecrets(t, testIssuerNamespace)
			kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
			protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{leaf}}}
			signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
			issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: validSpec("https://example.test/cmp")}
			issuer.Spec.Protocol.MACResponseProtection = test.configure
			request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testIssuerNamespace}, details: issuersigner.CertificateDetails{CSR: testCSR(t)}}
			if _, err := signer.Sign(context.Background(), request, issuer); err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if protocolClient.request.AllowSignedMACResponse != test.allowed {
				t.Fatalf("expected AllowSignedMACResponse %t, got %t", test.allowed, protocolClient.request.AllowSignedMACResponse)
			}
		})
	}
}

// TestSignUsesKURForCertManagerRenewals verifies authorized new-key and same-key renewals persist and execute KUR.
func TestSignUsesKURForCertManagerRenewals(t *testing.T) {
	for _, test := range []struct {
		name      string
		rotateKey bool
	}{
		{name: "rotation policy Always", rotateKey: true},
		{name: "rotation policy Never", rotateKey: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
			issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace, UID: types.UID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), Generation: 1}, Spec: validSpec("https://example.test/cmp")}
			issuer.Spec.Protocol.Renewal = cmpv1alpha1.RenewalKUR
			issuer.Spec.Endpoint.RenewalURL = "https://example.test/keyupdate"
			request, certificate, currentSecret, stagedSecret := testKURRequestObjects(t, issuer, test.rotateKey)
			issued := issuedCertificateFor(t, request.details.CSR)
			kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, certificate, currentSecret, stagedSecret).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
			protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}
			signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
			bundle, err := signer.Sign(context.Background(), request, issuer)
			if err != nil || len(bundle.ChainPEM) == 0 {
				t.Fatalf("KUR Sign failed: %v", err)
			}
			if protocolClient.kurCalls != 1 || protocolClient.calls != 0 {
				t.Fatalf("expected one KUR and no P10CR calls, got %d and %d", protocolClient.kurCalls, protocolClient.calls)
			}
			if protocolClient.request.Operation != protocol.OperationKUR || protocolClient.request.RequestedPrivateKey == nil || protocolClient.request.Protection.Signature == nil {
				t.Fatal("KUR request did not carry both authorized key proofs")
			}
			if protocolClient.request.EndpointURL != issuer.Spec.Endpoint.RenewalURL {
				t.Fatalf("expected KUR endpoint %q, got %q", issuer.Spec.Endpoint.RenewalURL, protocolClient.request.EndpointURL)
			}
			stored := &cmpv1alpha1.CMPTransaction{}
			if err := kubeClient.Get(context.Background(), types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}, stored); err != nil {
				t.Fatalf("read KUR transaction: %v", err)
			}
			if stored.Spec.Operation != cmpv1alpha1.TransactionOperationKUR || len(stored.Spec.ConfigurationDigest) != sha256.Size*2 {
				t.Fatalf("expected persisted KUR operation and configuration digest, got %q and %q", stored.Spec.Operation, stored.Spec.ConfigurationDigest)
			}
		})
	}
}

// TestSignRetriesKURUnderTheRecordedTransactionID verifies restart-safe retries stay pinned to KUR.
func TestSignRetriesKURUnderTheRecordedTransactionID(t *testing.T) {
	auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace, UID: types.UID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), Generation: 1}, Spec: validSpec("https://example.test/cmp")}
	issuer.Spec.Protocol.Renewal = cmpv1alpha1.RenewalKUR
	request, certificate, currentSecret, stagedSecret := testKURRequestObjects(t, issuer, true)
	issued := issuedCertificateFor(t, request.details.CSR)
	kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, certificate, currentSecret, stagedSecret).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
	protocolClient := &fakeProtocolClient{queue: []fakeExchange{
		{err: &protocol.Error{Kind: protocol.ErrorKindRetryable, Operation: testHTTPExchangeOperation, Failure: testFailureSystemUnavailable, Err: errors.New("connection refused")}},
		{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}},
	}}
	signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
	if _, err := signer.Sign(context.Background(), request, issuer); err == nil {
		t.Fatal("expected the first KUR exchange to fail retryably")
	}
	stored := &cmpv1alpha1.CMPTransaction{}
	transactionKey := types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}
	if err := kubeClient.Get(context.Background(), transactionKey, stored); err != nil {
		t.Fatalf("read recorded KUR transaction: %v", err)
	}
	recordedID := append([]byte(nil), stored.Spec.TransactionID...)
	if _, err := signer.Sign(context.Background(), request, issuer); err != nil {
		t.Fatalf("retry KUR: %v", err)
	}
	if protocolClient.kurCalls != 2 || protocolClient.calls != 0 || protocolClient.polls != 0 {
		t.Fatalf("expected two KUR calls with no P10CR or poll calls, got %d, %d and %d", protocolClient.kurCalls, protocolClient.calls, protocolClient.polls)
	}
	if !slices.Equal(protocolClient.request.TransactionID, recordedID) {
		t.Fatal("expected the KUR retry to reuse the recorded transaction ID")
	}
}

// TestSignRejectsAnnotationOnlyKURAuthorization verifies arbitrary private-key annotations cannot trigger Secret reads.
func TestSignRejectsAnnotationOnlyKURAuthorization(t *testing.T) {
	auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
	unrelated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testUnrelatedPrivateKeySecret, Namespace: testIssuerNamespace}, Data: map[string][]byte{corev1.TLSPrivateKeyKey: []byte("sensitive")}}
	baseClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, unrelated).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
	recording := &recordingClient{Client: baseClient}
	protocolClient := &fakeProtocolClient{}
	signer := &Signer{KubeClient: recording, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(baseClient)}
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: validSpec("https://example.test/cmp")}
	issuer.Spec.Protocol.Renewal = cmpv1alpha1.RenewalKUR
	request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testIssuerNamespace, UID: testRequestUID, Annotations: map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "2", certmanagerv1.CertificateRequestPrivateKeyAnnotationKey: testUnrelatedPrivateKeySecret}}, details: issuersigner.CertificateDetails{CSR: testCSR(t)}}
	_, err := signer.Sign(context.Background(), request, issuer)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent KUR authorization failure, got %v", err)
	}
	for _, read := range recording.readNames() {
		if read.Name == testUnrelatedPrivateKeySecret {
			t.Fatal("signer read an annotation-selected Secret without a verified Certificate owner chain")
		}
	}
	if protocolClient.kurCalls != 0 || protocolClient.calls != 0 {
		t.Fatal("signer sent CMP traffic after KUR authorization failed")
	}
	stored := &cmpv1alpha1.CMPTransaction{}
	if err := baseClient.Get(context.Background(), types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}, stored); !apierrors.IsNotFound(err) {
		t.Fatalf("expected no transaction before KUR authorization, got %v", err)
	}
}
