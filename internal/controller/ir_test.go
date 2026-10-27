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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// testIRIssuer returns a PasswordBasedMac issuer whose initial enrollment is IR.
func testIRIssuer() *cmpv1alpha1.CMPIssuer {
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace, UID: types.UID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), Generation: 1}, Spec: validSpec("https://example.test/cmp")}
	issuer.Spec.Protocol.InitialEnrollment = cmpv1alpha1.InitialEnrollmentIR
	return issuer
}

// testIRRequestObjects builds the first-revision cert-manager ownership chain and the staged key
// Secret of a Certificate that has no certificate yet.
func testIRRequestObjects(t *testing.T, issuer *cmpv1alpha1.CMPIssuer, requestedKey crypto.Signer) (*fakeCertificateRequest, *certmanagerv1.Certificate, *corev1.Secret) {
	t.Helper()
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testWorkloadCommonName}, DNSNames: []string{"workload.example"}}, requestedKey)
	if err != nil {
		t.Fatal(err)
	}
	nextPrivateKeySecretName := testNextPrivateKeySecret
	certificate := &certmanagerv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: testWorkloadCommonName, Namespace: testIssuerNamespace, UID: types.UID("22222222-2222-2222-2222-222222222222")}, Spec: certmanagerv1.CertificateSpec{SecretName: "workload-tls", IssuerRef: cmmeta.IssuerReference{Name: issuer.Name, Kind: cmpv1alpha1.TransactionIssuerKindNamespaced, Group: cmpv1alpha1.GroupVersion.Group}}, Status: certmanagerv1.CertificateStatus{NextPrivateKeySecretName: &nextPrivateKeySecretName}}
	controllerReference := *metav1.NewControllerRef(certificate, certmanagerv1.SchemeGroupVersion.WithKind(certificateKind))
	stagedSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: nextPrivateKeySecretName, Namespace: testIssuerNamespace, Labels: map[string]string{certmanagerv1.IsNextPrivateKeySecretLabelKey: "true"}, OwnerReferences: []metav1.OwnerReference{controllerReference}}, Data: map[string][]byte{corev1.TLSPrivateKeyKey: testKURKeyPEM(t, requestedKey)}}
	request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testIssuerNamespace, UID: testRequestUID, Annotations: map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "1", certmanagerv1.CertificateRequestPrivateKeyAnnotationKey: nextPrivateKeySecretName}, OwnerReferences: []metav1.OwnerReference{controllerReference}}, details: issuersigner.CertificateDetails{CSR: pem.EncodeToMemory(&pem.Block{Type: testCSRBlockType, Bytes: requestDER})}}
	return request, certificate, stagedSecret
}

// testECDSAKey generates a P-256 workload key.
func testECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestSelectedTransactionOperation verifies the first revision uses initialEnrollment and later
// revisions the renewal operation, which follows initialEnrollment when omitted.
func TestSelectedTransactionOperation(t *testing.T) {
	for _, test := range []struct {
		name     string
		initial  string
		renewal  string
		revision string
		want     string
		failure  string
	}{
		{name: "P10CR without a revision", initial: cmpv1alpha1.InitialEnrollmentP10CR, want: cmpv1alpha1.TransactionOperationP10CR},
		{name: "P10CR renewal by default", initial: cmpv1alpha1.InitialEnrollmentP10CR, revision: "2", want: cmpv1alpha1.TransactionOperationP10CR},
		{name: "P10CR first revision before KUR", initial: cmpv1alpha1.InitialEnrollmentP10CR, renewal: cmpv1alpha1.RenewalKUR, revision: "1", want: cmpv1alpha1.TransactionOperationP10CR},
		{name: "KUR renewal after P10CR", initial: cmpv1alpha1.InitialEnrollmentP10CR, renewal: cmpv1alpha1.RenewalKUR, revision: "2", want: cmpv1alpha1.TransactionOperationKUR},
		{name: "P10CR for a standalone request under KUR", initial: cmpv1alpha1.InitialEnrollmentP10CR, renewal: cmpv1alpha1.RenewalKUR, want: cmpv1alpha1.TransactionOperationP10CR},
		{name: "IR first revision", initial: cmpv1alpha1.InitialEnrollmentIR, revision: "1", want: cmpv1alpha1.TransactionOperationIR},
		{name: "KUR renewal follows IR", initial: cmpv1alpha1.InitialEnrollmentIR, revision: "2", want: cmpv1alpha1.TransactionOperationKUR},
		{name: "explicit KUR renewal after IR", initial: cmpv1alpha1.InitialEnrollmentIR, renewal: cmpv1alpha1.RenewalKUR, revision: "5", want: cmpv1alpha1.TransactionOperationKUR},
		{name: "explicit P10CR renewal after IR", initial: cmpv1alpha1.InitialEnrollmentIR, renewal: cmpv1alpha1.RenewalP10CR, revision: "2", want: cmpv1alpha1.TransactionOperationP10CR},
		{name: "IR refuses a standalone request", initial: cmpv1alpha1.InitialEnrollmentIR, failure: "IR needs a CertificateRequest that cert-manager created for a Certificate"},
		{name: "IR refuses revision zero", initial: cmpv1alpha1.InitialEnrollmentIR, revision: "0", failure: "must be positive"},
		{name: "IR refuses an invalid revision", initial: cmpv1alpha1.InitialEnrollmentIR, revision: "one", failure: "absent or invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer := testIRIssuer()
			issuer.Spec.Protocol.InitialEnrollment = test.initial
			issuer.Spec.Protocol.Renewal = test.renewal
			request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testIssuerNamespace}}
			if test.revision != "" {
				request.Annotations = map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: test.revision}
			}
			operation, err := selectedTransactionOperation(issuer, request)
			if test.failure != "" {
				if err == nil || !strings.Contains(err.Error(), test.failure) {
					t.Fatalf("expected a failure containing %q, got %q and %v", test.failure, operation, err)
				}
				return
			}
			if err != nil || operation != test.want {
				t.Fatalf("expected %s, got %q and %v", test.want, operation, err)
			}
		})
	}
}

// TestSignUsesIRForTheFirstRevision verifies an IR issuer proves possession with the staged key
// under its own protection and reads no other workload Secret.
func TestSignUsesIRForTheFirstRevision(t *testing.T) {
	auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
	issuer := testIRIssuer()
	issuer.Spec.Endpoint.RenewalURL = "https://example.test/keyupdate"
	requestedKey := testECDSAKey(t)
	request, certificate, stagedSecret := testIRRequestObjects(t, issuer, requestedKey)
	output := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: certificate.Spec.SecretName, Namespace: testIssuerNamespace}, Data: map[string][]byte{corev1.TLSPrivateKeyKey: []byte("unrelated")}}
	issued := issuedCertificateFor(t, request.details.CSR)
	baseClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, certificate, stagedSecret, output).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
	recording := &recordingClient{Client: baseClient}
	protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}
	signer := &Signer{KubeClient: recording, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(baseClient)}
	bundle, err := signer.Sign(context.Background(), request, issuer)
	if err != nil || len(bundle.ChainPEM) == 0 {
		t.Fatalf("IR Sign failed: %v", err)
	}
	if protocolClient.irCalls != 1 || protocolClient.calls != 0 || protocolClient.kurCalls != 0 {
		t.Fatalf("expected one IR call, got %d IR, %d P10CR and %d KUR", protocolClient.irCalls, protocolClient.calls, protocolClient.kurCalls)
	}
	sent := protocolClient.request
	if sent.Operation != protocol.OperationIR || sent.Protection.Password == nil || sent.Protection.Signature != nil {
		t.Fatal("expected an IR under the issuer's PasswordBasedMac protection")
	}
	if sent.RequestedPrivateKey == nil || !protocol.PublicKeysEqual(sent.RequestedPrivateKey.Public(), requestedKey.Public()) {
		t.Fatal("expected the staged key to prove possession")
	}
	if sent.EndpointURL != issuer.Spec.Endpoint.URL || !sent.RequestedNotAfter.IsZero() {
		t.Fatalf("expected the initial endpoint and no requested validity, got %q and %s", sent.EndpointURL, sent.RequestedNotAfter)
	}
	for _, read := range recording.readNames() {
		if read.Name == certificate.Spec.SecretName {
			t.Fatal("IR read the Certificate output Secret")
		}
	}
	stored := &cmpv1alpha1.CMPTransaction{}
	if err := baseClient.Get(context.Background(), types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}, stored); err != nil {
		t.Fatalf("read IR transaction: %v", err)
	}
	if stored.Spec.Operation != cmpv1alpha1.TransactionOperationIR || len(stored.Spec.ConfigurationDigest) != sha256.Size*2 {
		t.Fatalf("expected persisted IR operation and configuration digest, got %q and %q", stored.Spec.Operation, stored.Spec.ConfigurationDigest)
	}
}

// TestSignRefusesUnauthorizedIR verifies the staged key is read only through the verified
// Certificate ownership chain and that a refused IR sends nothing and records nothing.
func TestSignRefusesUnauthorizedIR(t *testing.T) {
	otherKey := testECDSAKey(t)
	for _, test := range []struct {
		name    string
		mutate  func(t *testing.T, request *fakeCertificateRequest, certificate *certmanagerv1.Certificate, staged *corev1.Secret)
		failure string
	}{
		{name: "a standalone CertificateRequest", mutate: func(_ *testing.T, request *fakeCertificateRequest, _ *certmanagerv1.Certificate, _ *corev1.Secret) {
			request.Annotations = map[string]string{certmanagerv1.CertificateRequestPrivateKeyAnnotationKey: testNextPrivateKeySecret}
			request.OwnerReferences = nil
		}, failure: "IR needs a CertificateRequest"},
		{name: "no controlling Certificate", mutate: func(_ *testing.T, request *fakeCertificateRequest, _ *certmanagerv1.Certificate, _ *corev1.Secret) {
			request.OwnerReferences = nil
		}, failure: "authorize IR CertificateRequest"},
		{name: "a Certificate that already holds a revision", mutate: func(_ *testing.T, _ *fakeCertificateRequest, certificate *certmanagerv1.Certificate, _ *corev1.Secret) {
			revision := 1
			certificate.Status.Revision = &revision
		}, failure: "does not immediately follow"},
		{name: "a Certificate of another issuer", mutate: func(_ *testing.T, _ *fakeCertificateRequest, certificate *certmanagerv1.Certificate, _ *corev1.Secret) {
			certificate.Spec.IssuerRef.Name = "other-issuer"
		}, failure: "different issuer"},
		{name: "an annotation the Certificate does not record", mutate: func(_ *testing.T, request *fakeCertificateRequest, _ *certmanagerv1.Certificate, _ *corev1.Secret) {
			request.Annotations[certmanagerv1.CertificateRequestPrivateKeyAnnotationKey] = testUnrelatedPrivateKeySecret
		}, failure: "authorize IR staged private key"},
		{name: "a staged Secret without the next-key label", mutate: func(_ *testing.T, _ *fakeCertificateRequest, _ *certmanagerv1.Certificate, staged *corev1.Secret) {
			delete(staged.Labels, certmanagerv1.IsNextPrivateKeySecretLabelKey)
		}, failure: "authorize IR staged private key"},
		{name: "a staged key that does not match the CSR", mutate: func(t *testing.T, _ *fakeCertificateRequest, _ *certmanagerv1.Certificate, staged *corev1.Secret) {
			staged.Data[corev1.TLSPrivateKeyKey] = testKURKeyPEM(t, otherKey)
		}, failure: "validate IR staged private key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
			issuer := testIRIssuer()
			request, certificate, stagedSecret := testIRRequestObjects(t, issuer, testECDSAKey(t))
			unrelated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testUnrelatedPrivateKeySecret, Namespace: testIssuerNamespace}, Data: map[string][]byte{corev1.TLSPrivateKeyKey: []byte("sensitive")}}
			test.mutate(t, request, certificate, stagedSecret)
			baseClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, certificate, stagedSecret, unrelated).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
			recording := &recordingClient{Client: baseClient}
			protocolClient := &fakeProtocolClient{}
			signer := &Signer{KubeClient: recording, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(baseClient)}
			_, err := signer.Sign(context.Background(), request, issuer)
			var permanent issuersigner.PermanentError
			if !errors.As(err, &permanent) || !strings.Contains(err.Error(), test.failure) {
				t.Fatalf("expected a permanent failure containing %q, got %v", test.failure, err)
			}
			if protocolClient.irCalls != 0 || protocolClient.calls != 0 || protocolClient.kurCalls != 0 {
				t.Fatal("signer sent CMP traffic after IR authorization failed")
			}
			for _, read := range recording.readNames() {
				if read.Name == testUnrelatedPrivateKeySecret {
					t.Fatal("signer read an annotation-selected Secret")
				}
			}
			stored := &cmpv1alpha1.CMPTransaction{}
			if err := baseClient.Get(context.Background(), types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}, stored); !apierrors.IsNotFound(err) {
				t.Fatalf("expected no transaction after a refused IR, got %v", err)
			}
		})
	}
}

// TestSignIRStagedKeyFingerprint verifies a retried IR keeps its operation and transaction ID while
// a staged key change stops the unfinished transaction.
func TestSignIRStagedKeyFingerprint(t *testing.T) {
	newFixture := func(t *testing.T) (*Signer, *fakeProtocolClient, client.Client, *cmpv1alpha1.CMPIssuer, *fakeCertificateRequest, *corev1.Secret) {
		t.Helper()
		auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
		issuer := testIRIssuer()
		request, certificate, stagedSecret := testIRRequestObjects(t, issuer, testECDSAKey(t))
		issued := issuedCertificateFor(t, request.details.CSR)
		kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, certificate, stagedSecret).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
		protocolClient := &fakeProtocolClient{queue: []fakeExchange{
			{err: &protocol.Error{Kind: protocol.ErrorKindRetryable, Operation: testHTTPExchangeOperation, Failure: testFailureSystemUnavailable, Err: errors.New("connection refused")}},
			{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}},
		}}
		signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
		if _, err := signer.Sign(context.Background(), request, issuer); err == nil {
			t.Fatal("expected the first IR exchange to fail retryably")
		}
		return signer, protocolClient, kubeClient, issuer, request, stagedSecret
	}

	t.Run("retry reuses the recorded transaction", func(t *testing.T) {
		signer, protocolClient, kubeClient, issuer, request, _ := newFixture(t)
		stored := &cmpv1alpha1.CMPTransaction{}
		if err := kubeClient.Get(context.Background(), types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}, stored); err != nil {
			t.Fatalf("read recorded IR transaction: %v", err)
		}
		if _, err := signer.Sign(context.Background(), request, issuer); err != nil {
			t.Fatalf("retry IR: %v", err)
		}
		if protocolClient.irCalls != 2 || protocolClient.calls != 0 || !slices.Equal(protocolClient.request.TransactionID, stored.Spec.TransactionID) {
			t.Fatalf("expected two IR calls under the recorded transaction ID, got %d IR and %d P10CR", protocolClient.irCalls, protocolClient.calls)
		}
	})

	t.Run("staged key change stops the transaction", func(t *testing.T) {
		signer, protocolClient, kubeClient, issuer, request, stagedSecret := newFixture(t)
		staged := &corev1.Secret{}
		if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(stagedSecret), staged); err != nil {
			t.Fatalf("read staged Secret: %v", err)
		}
		// A different encoding of the same key changes the consumed data without failing the CSR check.
		block, _ := pem.Decode(staged.Data[corev1.TLSPrivateKeyKey])
		staged.Data[corev1.TLSPrivateKeyKey] = append(pem.EncodeToMemory(block), '\n')
		if err := kubeClient.Update(context.Background(), staged); err != nil {
			t.Fatalf("rewrite staged Secret: %v", err)
		}
		_, err := signer.Sign(context.Background(), request, issuer)
		var permanent issuersigner.PermanentError
		if !errors.As(err, &permanent) || !strings.Contains(err.Error(), "credentials changed") {
			t.Fatalf("expected the rewritten staged key to stop the transaction, got %v", err)
		}
		if protocolClient.irCalls != 1 {
			t.Fatalf("expected no IR retry after the staged key changed, got %d calls", protocolClient.irCalls)
		}
	})
}

// TestSignRequestsValidity verifies requestedValidity Duration asks an IR or KUR for the
// CertificateRequest duration and leaves P10CR and an unset duration alone. The request is the
// issuer-lib wrapper of a real CertificateRequest, whose spec.duration the signer reads.
func TestSignRequestsValidity(t *testing.T) {
	duration := &metav1.Duration{Duration: 720 * time.Hour}
	for _, test := range []struct {
		name      string
		mode      string
		renewal   string
		kur       bool
		duration  *metav1.Duration
		requested bool
	}{
		{name: "IR asks for the duration", mode: cmpv1alpha1.RequestedValidityDuration, duration: duration, requested: true},
		{name: "KUR asks for the duration", mode: cmpv1alpha1.RequestedValidityDuration, kur: true, duration: duration, requested: true},
		{name: "Omit asks for nothing", mode: cmpv1alpha1.RequestedValidityOmit, duration: duration},
		{name: "an unset duration asks for nothing", mode: cmpv1alpha1.RequestedValidityDuration},
		{name: "P10CR renewal asks for nothing", mode: cmpv1alpha1.RequestedValidityDuration, renewal: cmpv1alpha1.RenewalP10CR, kur: true, duration: duration},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
			issuer := testIRIssuer()
			issuer.Spec.Protocol.RequestedValidity = test.mode
			issuer.Spec.Protocol.Renewal = test.renewal
			var fakeRequest *fakeCertificateRequest
			objects := []client.Object{auth, trust}
			if test.kur {
				request, certificate, currentSecret, stagedSecret := testKURRequestObjects(t, issuer, true)
				fakeRequest = request
				objects = append(objects, certificate, currentSecret, stagedSecret)
			} else {
				request, certificate, stagedSecret := testIRRequestObjects(t, issuer, testECDSAKey(t))
				fakeRequest = request
				objects = append(objects, certificate, stagedSecret)
			}
			request := issuersigner.CertificateRequestObjectFromCertificateRequest(&certmanagerv1.CertificateRequest{ObjectMeta: fakeRequest.ObjectMeta, Spec: certmanagerv1.CertificateRequestSpec{Request: fakeRequest.details.CSR, Duration: test.duration}})
			issued := issuedCertificateFor(t, fakeRequest.details.CSR)
			kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
			protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}
			signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
			started := time.Now()
			if _, err := signer.Sign(context.Background(), request, issuer); err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			notAfter := protocolClient.request.RequestedNotAfter
			if !test.requested {
				if !notAfter.IsZero() {
					t.Fatalf("expected no requested validity, got %s", notAfter)
				}
				return
			}
			want := started.Add(test.duration.Duration)
			if notAfter.Location() != time.UTC || notAfter.Nanosecond() != 0 || notAfter.Before(want.Add(-2*time.Second)) || notAfter.After(want.Add(2*time.Second)) {
				t.Fatalf("expected a whole-second UTC notAfter near %s, got %s", want, notAfter)
			}
		})
	}
}

// TestCRMFOperationsAgainstAPIServer verifies the schema accepts IR, leaves renewal to follow
// initialEnrollment and refuses a requested validity that no selected operation can carry and a
// renewal fallback without KUR.
func TestCRMFOperationsAgainstAPIServer(t *testing.T) {
	kube := startEnvtest(t)
	ctx := context.Background()
	for i, test := range []struct {
		name    string
		mutate  func(*cmpv1alpha1.ProtocolSpec)
		valid   bool
		renewal string
	}{
		{name: "IR renews with KUR", mutate: func(spec *cmpv1alpha1.ProtocolSpec) { spec.InitialEnrollment = cmpv1alpha1.InitialEnrollmentIR }, valid: true, renewal: cmpv1alpha1.TransactionOperationKUR},
		{name: "P10CR renews with P10CR", mutate: func(*cmpv1alpha1.ProtocolSpec) {}, valid: true, renewal: cmpv1alpha1.TransactionOperationP10CR},
		{name: "IR with requested validity", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.InitialEnrollment = cmpv1alpha1.InitialEnrollmentIR
			spec.RequestedValidity = cmpv1alpha1.RequestedValidityDuration
		}, valid: true, renewal: cmpv1alpha1.TransactionOperationKUR},
		{name: "KUR renewal with requested validity", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.Renewal = cmpv1alpha1.RenewalKUR
			spec.RequestedValidity = cmpv1alpha1.RequestedValidityDuration
		}, valid: true, renewal: cmpv1alpha1.TransactionOperationKUR},
		{name: "requested validity with only P10CR", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.RequestedValidity = cmpv1alpha1.RequestedValidityDuration
		}},
		{name: "requested validity with P10CR renewal", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.Renewal = cmpv1alpha1.RenewalP10CR
			spec.RequestedValidity = cmpv1alpha1.RequestedValidityDuration
		}},
		{name: "unknown initial enrollment", mutate: func(spec *cmpv1alpha1.ProtocolSpec) { spec.InitialEnrollment = "CR" }},
		{name: "renewal fallback for implied KUR", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.InitialEnrollment = cmpv1alpha1.InitialEnrollmentIR
			spec.RenewalFallback = cmpv1alpha1.RenewalFallbackInitialEnrollment
		}, valid: true, renewal: cmpv1alpha1.TransactionOperationKUR},
		{name: "renewal fallback for KUR after P10CR", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.Renewal = cmpv1alpha1.RenewalKUR
			spec.RenewalFallback = cmpv1alpha1.RenewalFallbackInitialEnrollment
		}, valid: true, renewal: cmpv1alpha1.TransactionOperationKUR},
		{name: "renewal fallback with implied P10CR", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.RenewalFallback = cmpv1alpha1.RenewalFallbackInitialEnrollment
		}},
		{name: "renewal fallback with P10CR renewal after IR", mutate: func(spec *cmpv1alpha1.ProtocolSpec) {
			spec.InitialEnrollment = cmpv1alpha1.InitialEnrollmentIR
			spec.Renewal = cmpv1alpha1.RenewalP10CR
			spec.RenewalFallback = cmpv1alpha1.RenewalFallbackInitialEnrollment
		}},
		{name: "unknown renewal fallback", mutate: func(spec *cmpv1alpha1.ProtocolSpec) { spec.RenewalFallback = "OnFailure" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer := &cmpv1alpha1.CMPClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("crmf-%d", i)}, Spec: validSpec("https://example.test/cmp")}
			test.mutate(&issuer.Spec.Protocol)
			err := kube.Create(ctx, issuer)
			if (err == nil) != test.valid {
				t.Fatalf("expected valid=%t, got %v", test.valid, err)
			}
			if !test.valid {
				return
			}
			stored := &cmpv1alpha1.CMPClusterIssuer{}
			if err := kube.Get(ctx, types.NamespacedName{Name: issuer.Name}, stored); err != nil {
				t.Fatal(err)
			}
			if _, err := validateSpec(&stored.Spec); err != nil {
				t.Fatalf("the API server accepted an issuer the controller rejects: %v", err)
			}
			if stored.Spec.Protocol.RequestedValidity == "" || stored.Spec.Protocol.RenewalFallback == "" {
				t.Fatal("expected requestedValidity and renewalFallback to be defaulted")
			}
			if operation := renewalOperation(stored.Spec.Protocol); operation != test.renewal {
				t.Fatalf("expected renewal %s, got %s with renewal %q", test.renewal, operation, stored.Spec.Protocol.Renewal)
			}
		})
	}

	t.Run("IR transaction", func(t *testing.T) {
		namespace := "crmf-transactions"
		if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
			t.Fatalf("create namespace: %v", err)
		}
		transaction := &cmpv1alpha1.CMPTransaction{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: namespace}, Spec: cmpv1alpha1.CMPTransactionSpec{CertificateRequestName: testRequestName, CertificateRequestUID: string(testRequestUID), TransactionID: []byte("ir-transaction"), Deadline: metav1.NewTime(time.Now().Add(time.Minute)), Operation: cmpv1alpha1.TransactionOperationIR}}
		if err := kube.Create(ctx, transaction); err != nil {
			t.Fatalf("an IR transaction is rejected by the API server: %v", err)
		}
		fallback := transaction.DeepCopy()
		fallback.ObjectMeta = metav1.ObjectMeta{Name: testRequestName + "-fallback", Namespace: namespace}
		fallback.Spec.RenewalFallback = cmpv1alpha1.RenewalFallbackCurrentCertificateMissing
		if err := kube.Create(ctx, fallback); err != nil {
			t.Fatalf("an IR fallback transaction is rejected by the API server: %v", err)
		}
		unknown := transaction.DeepCopy()
		unknown.ObjectMeta = metav1.ObjectMeta{Name: testRequestName + "-unknown", Namespace: namespace}
		unknown.Spec.RenewalFallback = "Revoked"
		if err := kube.Create(ctx, unknown); err == nil {
			t.Fatal("expected an unknown renewal fallback reason to be rejected")
		}
	})
}
