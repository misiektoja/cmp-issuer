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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
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

const (
	testRenewalURL               = "https://example.test/keyupdate"
	testForeignCertificateName   = "other-workload"
	testNotNextRevision          = "does not immediately follow"
	testIRStagedKeyAuthorization = "authorize IR staged private key"
	testFallbackNotAllowed       = "does not allow"
)

// renewalFallbackFixture holds a second-revision request of a Certificate whose issuer falls back
// from KUR, together with its current and staged key Secrets.
type renewalFallbackFixture struct {
	issuer      *cmpv1alpha1.CMPIssuer
	request     *fakeCertificateRequest
	certificate *certmanagerv1.Certificate
	current     *corev1.Secret
	staged      *corev1.Secret
	currentKey  crypto.Signer
	stagedKey   crypto.Signer
}

// newRenewalFallbackFixture builds the fixture for an IR issuer that renews with KUR and falls back
// to IR. The current Secret holds a currently valid certificate.
func newRenewalFallbackFixture(t *testing.T) *renewalFallbackFixture {
	t.Helper()
	issuer := testIRIssuer()
	issuer.Spec.Protocol.RenewalFallback = cmpv1alpha1.RenewalFallbackInitialEnrollment
	currentKey, stagedKey := testECDSAKey(t), testECDSAKey(t)
	request, certificate, current, staged := testKURRequestObjectsWithKeys(t, issuer, currentKey, stagedKey)
	return &renewalFallbackFixture{issuer: issuer, request: request, certificate: certificate, current: current, staged: staged, currentKey: currentKey, stagedKey: stagedKey}
}

// objects returns the credential and workload objects of the fixture, leaving out the current
// Secret when it is nil.
func (f *renewalFallbackFixture) objects(t *testing.T) []client.Object {
	t.Helper()
	auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
	objects := []client.Object{auth, trust, f.certificate, f.staged}
	if f.current != nil {
		objects = append(objects, f.current)
	}
	return objects
}

// testCertificateWithValidity issues a self-signed workload leaf PEM for key with the given validity.
func testCertificateWithValidity(t *testing.T, key crypto.Signer, notBefore time.Time, notAfter time.Time) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(92), Subject: pkix.Name{CommonName: testWorkloadCommonName}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemCertificateBlockType, Bytes: certificateDER})
}

// recordedEvents drains the events a fake recorder holds.
func recordedEvents(recorder *events.FakeRecorder) []string {
	var recorded []string
	for {
		select {
		case event := <-recorder.Events:
			recorded = append(recorded, event)
		default:
			return recorded
		}
	}
}

// storedTransaction reads the CMPTransaction of the test request and returns nil when none exists.
func storedTransaction(t *testing.T, kubeClient client.Client) *cmpv1alpha1.CMPTransaction {
	t.Helper()
	stored := &cmpv1alpha1.CMPTransaction{}
	err := kubeClient.Get(context.Background(), types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}, stored)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read CMP transaction: %v", err)
	}
	return stored
}

// TestRenewalFallbackOperation verifies the fallback applies only to a KUR renewal whose issuer
// enables it and that it selects the issuer's initial enrollment operation.
func TestRenewalFallbackOperation(t *testing.T) {
	for _, test := range []struct {
		name     string
		initial  string
		renewal  string
		fallback string
		want     string
	}{
		{name: "IR issuer with implied KUR", initial: cmpv1alpha1.InitialEnrollmentIR, fallback: cmpv1alpha1.RenewalFallbackInitialEnrollment, want: cmpv1alpha1.TransactionOperationIR},
		{name: "IR issuer with explicit KUR", initial: cmpv1alpha1.InitialEnrollmentIR, renewal: cmpv1alpha1.RenewalKUR, fallback: cmpv1alpha1.RenewalFallbackInitialEnrollment, want: cmpv1alpha1.TransactionOperationIR},
		{name: "P10CR issuer with KUR", initial: cmpv1alpha1.InitialEnrollmentP10CR, renewal: cmpv1alpha1.RenewalKUR, fallback: cmpv1alpha1.RenewalFallbackInitialEnrollment, want: cmpv1alpha1.TransactionOperationP10CR},
		{name: "fallback None", initial: cmpv1alpha1.InitialEnrollmentIR, fallback: cmpv1alpha1.RenewalFallbackNone},
		{name: "fallback unset", initial: cmpv1alpha1.InitialEnrollmentIR},
		{name: "P10CR renewal", initial: cmpv1alpha1.InitialEnrollmentIR, renewal: cmpv1alpha1.RenewalP10CR, fallback: cmpv1alpha1.RenewalFallbackInitialEnrollment},
		{name: "P10CR issuer with implied P10CR", initial: cmpv1alpha1.InitialEnrollmentP10CR, fallback: cmpv1alpha1.RenewalFallbackInitialEnrollment},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer := testIRIssuer()
			issuer.Spec.Protocol.InitialEnrollment = test.initial
			issuer.Spec.Protocol.Renewal = test.renewal
			issuer.Spec.Protocol.RenewalFallback = test.fallback
			if operation := renewalFallbackOperation(issuer); operation != test.want {
				t.Fatalf("expected %q, got %q", test.want, operation)
			}
			cluster := &cmpv1alpha1.CMPClusterIssuer{Spec: issuer.Spec}
			if operation := renewalFallbackOperation(cluster); operation != test.want {
				t.Fatalf("expected %q for a cluster issuer, got %q", test.want, operation)
			}
		})
	}
}

// TestClassifyRenewalFallback verifies a renewal falls back only when the current Secret is absent or
// when cert-manager wrote it for the Certificate without a certificate or with an expired one. Every
// other current Secret leaves the request to KUR. An unauthorized owner chain fails before the Secret
// is read.
func TestClassifyRenewalFallback(t *testing.T) {
	now := time.Now()
	foreign := &certmanagerv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: testForeignCertificateName, Namespace: testIssuerNamespace, UID: types.UID("44444444-4444-4444-4444-444444444444")}}
	ownerKind := certmanagerv1.SchemeGroupVersion.WithKind(certificateKind)
	for _, test := range []struct {
		name    string
		mutate  func(t *testing.T, f *renewalFallbackFixture)
		at      func(f *renewalFallbackFixture) time.Time
		want    string
		failure string
	}{
		{name: "a currently valid certificate stays with KUR"},
		{name: "an absent Secret is missing", want: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current = nil
		}},
		{name: "a Secret without tls.crt is missing", want: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			delete(f.current.Data, corev1.TLSCertKey)
		}},
		{name: "an empty tls.crt is missing", want: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current.Data[corev1.TLSCertKey] = nil
		}},
		{name: "an expired certificate is expired", want: cmpv1alpha1.RenewalFallbackCurrentCertificateExpired, mutate: func(t *testing.T, f *renewalFallbackFixture) {
			f.current.Data[corev1.TLSCertKey] = testCertificateWithValidity(t, f.currentKey, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}},
		{name: "a certificate at its notAfter is expired", want: cmpv1alpha1.RenewalFallbackCurrentCertificateExpired, at: func(f *renewalFallbackFixture) time.Time {
			certificates, _ := protocol.ParseCertificates(f.current.Data[corev1.TLSCertKey])
			return certificates[0].NotAfter
		}},
		{name: "a certificate that is not yet valid stays with KUR", mutate: func(t *testing.T, f *renewalFallbackFixture) {
			f.current.Data[corev1.TLSCertKey] = testCertificateWithValidity(t, f.currentKey, now.Add(time.Hour), now.Add(2*time.Hour))
		}},
		{name: "an unparseable certificate stays with KUR", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current.Data[corev1.TLSCertKey] = []byte("not a certificate")
		}},
		{name: "an unannotated Secret without a certificate stays with KUR", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			delete(f.current.Annotations, certmanagerv1.CertificateNameKey)
			delete(f.current.Data, corev1.TLSCertKey)
		}},
		{name: "a Secret written for another Certificate stays with KUR", mutate: func(t *testing.T, f *renewalFallbackFixture) {
			f.current.Annotations[certmanagerv1.CertificateNameKey] = foreign.Name
			f.current.Data[corev1.TLSCertKey] = testCertificateWithValidity(t, f.currentKey, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}},
		{name: "a Secret controlled by another Certificate stays with KUR", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(foreign, ownerKind)}
			delete(f.current.Data, corev1.TLSCertKey)
		}},
		{name: "a Certificate of another issuer fails", failure: "different issuer", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.certificate.Spec.IssuerRef.Name = "other-issuer"
			f.current = nil
		}},
		{name: "a request that skips a revision fails", failure: testNotNextRevision, mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.request.Annotations[certmanagerv1.CertificateRequestRevisionAnnotationKey] = "3"
			f.current = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRenewalFallbackFixture(t)
			if test.mutate != nil {
				test.mutate(t, f)
			}
			moment := now
			if test.at != nil {
				moment = test.at(f)
			}
			kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(f.objects(t)...).Build()
			signer := &Signer{KubeClient: kubeClient}
			fallback, configurationErr := signer.classifyRenewalFallback(context.Background(), f.request, f.issuer, moment)
			if test.failure != "" {
				if configurationErr == nil || !configurationErr.Permanent || !strings.Contains(configurationErr.Error(), test.failure) {
					t.Fatalf("expected a permanent failure containing %q, got %v", test.failure, configurationErr)
				}
				return
			}
			if configurationErr != nil {
				t.Fatalf("classify: %v", configurationErr)
			}
			if test.want == "" {
				if fallback != nil {
					t.Fatalf("expected KUR, got fallback %+v", fallback)
				}
				return
			}
			if fallback == nil || fallback.Reason != test.want || fallback.Certificate != f.certificate.Name || fallback.Secret != f.certificate.Spec.SecretName {
				t.Fatalf("expected %s for the Certificate Secret, got %+v", test.want, fallback)
			}
			if (fallback.Expired != nil) != (test.want == cmpv1alpha1.RenewalFallbackCurrentCertificateExpired) {
				t.Fatalf("expected the expired certificate only for %s, got %v", cmpv1alpha1.RenewalFallbackCurrentCertificateExpired, fallback.Expired)
			}
		})
	}
}

// TestSignRenewalFallback verifies a renewal whose current certificate is missing or expired is
// enrolled with the initial enrollment operation, recorded with its reason and reported, while a
// usable or foreign current Secret keeps the KUR behavior.
func TestSignRenewalFallback(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name      string
		mutate    func(t *testing.T, f *renewalFallbackFixture)
		operation string
		reason    string
		event     string
		failure   string
	}{
		{name: "a deleted Secret falls back to IR", operation: cmpv1alpha1.TransactionOperationIR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, event: "is missing or holds no certificate", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current = nil
		}},
		{name: "an expired certificate falls back to IR", operation: cmpv1alpha1.TransactionOperationIR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateExpired, event: "expired at", mutate: func(t *testing.T, f *renewalFallbackFixture) {
			f.current.Data[corev1.TLSCertKey] = testCertificateWithValidity(t, f.currentKey, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}},
		{name: "a P10CR issuer falls back to P10CR", operation: cmpv1alpha1.TransactionOperationP10CR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, event: "Renewing with P10CR", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.issuer.Spec.Protocol.InitialEnrollment = cmpv1alpha1.InitialEnrollmentP10CR
			f.issuer.Spec.Protocol.Renewal = cmpv1alpha1.RenewalKUR
			f.current = nil
		}},
		{name: "a valid certificate renews with KUR", operation: cmpv1alpha1.TransactionOperationKUR},
		{name: "a Secret of another Certificate fails as KUR does", failure: "authorize KUR current certificate", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current.Annotations[certmanagerv1.CertificateNameKey] = testForeignCertificateName
			delete(f.current.Data, corev1.TLSCertKey)
		}},
		{name: "without the fallback a deleted Secret fails permanently", failure: `current certificate Secret "workload-tls" does not exist, so KUR cannot authenticate: set renewalFallback to InitialEnrollment`, mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.issuer.Spec.Protocol.RenewalFallback = cmpv1alpha1.RenewalFallbackNone
			f.current = nil
		}},
		{name: "without the fallback an empty Secret fails permanently", failure: `current certificate Secret "workload-tls" holds no certificate`, mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.issuer.Spec.Protocol.RenewalFallback = cmpv1alpha1.RenewalFallbackNone
			delete(f.current.Data, corev1.TLSCertKey)
		}},
		{name: "without the fallback an expired certificate fails with badTime", failure: "certificate being updated is not currently valid", mutate: func(t *testing.T, f *renewalFallbackFixture) {
			f.issuer.Spec.Protocol.RenewalFallback = cmpv1alpha1.RenewalFallbackNone
			f.current.Data[corev1.TLSCertKey] = testCertificateWithValidity(t, f.currentKey, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRenewalFallbackFixture(t)
			f.issuer.Spec.Endpoint.RenewalURL = testRenewalURL
			if test.mutate != nil {
				test.mutate(t, f)
			}
			// The issuer-lib wrapper of a real CertificateRequest carries the object an Event refers to.
			request := issuersigner.CertificateRequestObjectFromCertificateRequest(&certmanagerv1.CertificateRequest{ObjectMeta: f.request.ObjectMeta, Spec: certmanagerv1.CertificateRequestSpec{Request: f.request.details.CSR}})
			issued := issuedCertificateFor(t, f.request.details.CSR)
			kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(f.objects(t)...).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
			protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}
			recorder := events.NewFakeRecorder(10)
			signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: recorder, ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
			_, err := signer.Sign(context.Background(), request, f.issuer)
			if test.failure != "" {
				assertRefusedRenewal(t, err, test.failure, protocolClient, kubeClient, recorder)
				return
			}
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			assertRenewalExchange(t, test.operation, protocolClient, f)
			stored := storedTransaction(t, kubeClient)
			if stored == nil || stored.Spec.Operation != test.operation || stored.Spec.RenewalFallback != test.reason {
				t.Fatalf("expected a %s transaction with fallback %q, got %+v", test.operation, test.reason, stored)
			}
			recorded := recordedEvents(recorder)
			if test.event == "" {
				if len(recorded) != 0 {
					t.Fatalf("expected no Event, got %q", recorded)
				}
				return
			}
			if len(recorded) != 1 || !strings.HasPrefix(recorded[0], "Warning "+eventRenewalFallback+" ") || !strings.Contains(recorded[0], test.event) {
				t.Fatalf("expected one %s Warning Event containing %q, got %q", eventRenewalFallback, test.event, recorded)
			}
		})
	}
}

// assertRefusedRenewal checks that a renewal failed permanently before any CMP traffic, transaction
// record or Event.
func assertRefusedRenewal(t *testing.T, err error, failure string, protocolClient *fakeProtocolClient, kubeClient client.Client, recorder *events.FakeRecorder) {
	t.Helper()
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) || !strings.Contains(err.Error(), failure) {
		t.Fatalf("expected a permanent failure containing %q, got %v", failure, err)
	}
	if protocolClient.irCalls != 0 || protocolClient.calls != 0 || protocolClient.kurCalls != 0 {
		t.Fatal("signer sent CMP traffic after the renewal failed")
	}
	if stored := storedTransaction(t, kubeClient); stored != nil {
		t.Fatalf("expected no transaction, got %s", stored.Spec.Operation)
	}
	if recorded := recordedEvents(recorder); len(recorded) != 0 {
		t.Fatalf("expected no Event, got %q", recorded)
	}
}

// assertRenewalExchange checks that a renewal sent one message of the operation, with the key,
// protection and endpoint that operation uses.
func assertRenewalExchange(t *testing.T, operation string, protocolClient *fakeProtocolClient, f *renewalFallbackFixture) {
	t.Helper()
	sent := protocolClient.request
	switch operation {
	case cmpv1alpha1.TransactionOperationIR:
		if protocolClient.irCalls != 1 || protocolClient.kurCalls != 0 || protocolClient.calls != 0 {
			t.Fatalf("expected one IR call, got %d IR, %d KUR and %d P10CR", protocolClient.irCalls, protocolClient.kurCalls, protocolClient.calls)
		}
		if sent.Operation != protocol.OperationIR || sent.Protection.Password == nil || sent.Protection.Signature != nil {
			t.Fatal("expected an IR under the issuer's PasswordBasedMac protection")
		}
		if sent.RequestedPrivateKey == nil || !protocol.PublicKeysEqual(sent.RequestedPrivateKey.Public(), f.stagedKey.Public()) {
			t.Fatal("expected the staged key to prove possession")
		}
		if sent.EndpointURL != f.issuer.Spec.Endpoint.URL {
			t.Fatalf("expected the initial enrollment endpoint, got %q", sent.EndpointURL)
		}
	case cmpv1alpha1.TransactionOperationP10CR:
		if protocolClient.calls != 1 || protocolClient.kurCalls != 0 || protocolClient.irCalls != 0 {
			t.Fatalf("expected one P10CR call, got %d P10CR, %d KUR and %d IR", protocolClient.calls, protocolClient.kurCalls, protocolClient.irCalls)
		}
		if sent.EndpointURL != f.issuer.Spec.Endpoint.URL || sent.RequestedPrivateKey != nil {
			t.Fatalf("expected a P10CR to the initial enrollment endpoint without a workload key, got %q", sent.EndpointURL)
		}
	case cmpv1alpha1.TransactionOperationKUR:
		if protocolClient.kurCalls != 1 || protocolClient.irCalls != 0 || protocolClient.calls != 0 {
			t.Fatalf("expected one KUR call, got %d KUR, %d IR and %d P10CR", protocolClient.kurCalls, protocolClient.irCalls, protocolClient.calls)
		}
		if sent.EndpointURL != f.issuer.Spec.Endpoint.RenewalURL {
			t.Fatalf("expected the renewal endpoint, got %q", sent.EndpointURL)
		}
	}
}

// TestSignResumesRenewalFallback verifies the recorded operation is authoritative. A recorded
// fallback keeps its operation when the current certificate returns and stops when the issuer no
// longer falls back. A recorded KUR never falls back.
func TestSignResumesRenewalFallback(t *testing.T) {
	retryable := &protocol.Error{Kind: protocol.ErrorKindRetryable, Operation: testHTTPExchangeOperation, Failure: testFailureSystemUnavailable, Err: errors.New("connection refused")}
	// start records a transaction whose first exchange fails retryably and returns the fixture and
	// request for a second reconcile.
	start := func(t *testing.T, deleteCurrent bool) (*renewalFallbackFixture, issuersigner.CertificateRequestObject, *Signer, *fakeProtocolClient, *events.FakeRecorder, client.Client) {
		t.Helper()
		f := newRenewalFallbackFixture(t)
		current := f.current
		if deleteCurrent {
			f.current = nil
		}
		request := issuersigner.CertificateRequestObjectFromCertificateRequest(&certmanagerv1.CertificateRequest{ObjectMeta: f.request.ObjectMeta, Spec: certmanagerv1.CertificateRequestSpec{Request: f.request.details.CSR}})
		issued := issuedCertificateFor(t, f.request.details.CSR)
		kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(f.objects(t)...).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
		protocolClient := &fakeProtocolClient{queue: []fakeExchange{{err: retryable}, {result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}}}
		recorder := events.NewFakeRecorder(10)
		signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: recorder, ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
		var pending issuersigner.PendingError
		if _, err := signer.Sign(context.Background(), request, f.issuer); !errors.As(err, &pending) {
			t.Fatalf("expected the first exchange to be retried, got %v", err)
		}
		f.current = current
		return f, request, signer, protocolClient, recorder, kubeClient
	}

	t.Run("a recorded fallback keeps IR after the certificate returns", func(t *testing.T) {
		f, request, signer, protocolClient, _, kubeClient := start(t, true)
		recorded := storedTransaction(t, kubeClient)
		if recorded == nil || recorded.Spec.Operation != cmpv1alpha1.TransactionOperationIR || recorded.Spec.RenewalFallback != cmpv1alpha1.RenewalFallbackCurrentCertificateMissing {
			t.Fatalf("expected a recorded IR fallback, got %+v", recorded)
		}
		if err := kubeClient.Create(context.Background(), f.current); err != nil {
			t.Fatalf("restore current Secret: %v", err)
		}
		if _, err := signer.Sign(context.Background(), request, f.issuer); err != nil {
			t.Fatalf("resume IR fallback: %v", err)
		}
		if protocolClient.irCalls != 2 || protocolClient.kurCalls != 0 || !slices.Equal(protocolClient.request.TransactionID, recorded.Spec.TransactionID) {
			t.Fatalf("expected two IR calls under the recorded transaction ID, got %d IR and %d KUR", protocolClient.irCalls, protocolClient.kurCalls)
		}
	})

	t.Run("the fallback is reported once", func(t *testing.T) {
		f, request, signer, _, recorder, _ := start(t, true)
		if recorded := recordedEvents(recorder); len(recorded) != 1 {
			t.Fatalf("expected one Event when the fallback is recorded, got %q", recorded)
		}
		if _, err := signer.Sign(context.Background(), request, f.issuer); err != nil {
			t.Fatalf("resume IR fallback: %v", err)
		}
		if recorded := recordedEvents(recorder); len(recorded) != 0 {
			t.Fatalf("expected no Event when the fallback resumes, got %q", recorded)
		}
	})

	t.Run("a recorded fallback stops when the issuer no longer falls back", func(t *testing.T) {
		f, request, signer, protocolClient, _, kubeClient := start(t, true)
		f.issuer.Spec.Protocol.RenewalFallback = cmpv1alpha1.RenewalFallbackNone
		_, err := signer.Sign(context.Background(), request, f.issuer)
		var permanent issuersigner.PermanentError
		if !errors.As(err, &permanent) || !strings.Contains(err.Error(), "falls back from KUR to an operation the issuer does not allow") {
			t.Fatalf("expected the recorded fallback to stop, got %v", err)
		}
		if protocolClient.irCalls != 1 || protocolClient.kurCalls != 0 {
			t.Fatalf("expected no further CMP traffic, got %d IR and %d KUR", protocolClient.irCalls, protocolClient.kurCalls)
		}
		if stored := storedTransaction(t, kubeClient); stored != nil {
			t.Fatal("expected the refused transaction to be removed")
		}
	})

	t.Run("a recorded KUR does not fall back", func(t *testing.T) {
		f, request, signer, protocolClient, _, kubeClient := start(t, false)
		if err := kubeClient.Delete(context.Background(), f.current); err != nil {
			t.Fatalf("delete current Secret: %v", err)
		}
		_, err := signer.Sign(context.Background(), request, f.issuer)
		var permanent issuersigner.PermanentError
		if !errors.As(err, &permanent) || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected the recorded KUR to fail without its current Secret, got %v", err)
		}
		if protocolClient.kurCalls != 1 || protocolClient.irCalls != 0 {
			t.Fatalf("expected no fallback after KUR was recorded, got %d KUR and %d IR", protocolClient.kurCalls, protocolClient.irCalls)
		}
	})
}

// TestValidateResumedTransactionRenewalFallback verifies a recorded fallback reason is accepted only
// with the operation the issuer falls back to from a KUR renewal.
func TestValidateResumedTransactionRenewalFallback(t *testing.T) {
	issuerRef := cmpv1alpha1.TransactionIssuerReference{Name: testIssuerName, Kind: cmpv1alpha1.TransactionIssuerKindNamespaced, UID: "issuer-uid", Generation: 1}
	for _, test := range []struct {
		name      string
		recorded  string
		reason    string
		operation string
		fallback  string
		failure   string
	}{
		{name: "a recorded IR fallback", recorded: cmpv1alpha1.TransactionOperationIR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, operation: cmpv1alpha1.TransactionOperationKUR, fallback: cmpv1alpha1.TransactionOperationIR},
		{name: "a recorded P10CR fallback", recorded: cmpv1alpha1.TransactionOperationP10CR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateExpired, operation: cmpv1alpha1.TransactionOperationKUR, fallback: cmpv1alpha1.TransactionOperationP10CR},
		{name: "a fallback the issuer no longer enables", recorded: cmpv1alpha1.TransactionOperationIR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, operation: cmpv1alpha1.TransactionOperationKUR, failure: testFallbackNotAllowed},
		{name: "a fallback to another operation", recorded: cmpv1alpha1.TransactionOperationP10CR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, operation: cmpv1alpha1.TransactionOperationKUR, fallback: cmpv1alpha1.TransactionOperationIR, failure: testFallbackNotAllowed},
		{name: "a fallback reason on a recorded KUR", recorded: cmpv1alpha1.TransactionOperationKUR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, operation: cmpv1alpha1.TransactionOperationKUR, fallback: cmpv1alpha1.TransactionOperationIR, failure: testFallbackNotAllowed},
		{name: "a fallback reason on a first revision", recorded: cmpv1alpha1.TransactionOperationIR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, operation: cmpv1alpha1.TransactionOperationIR, fallback: cmpv1alpha1.TransactionOperationIR, failure: testFallbackNotAllowed},
		{name: "an unknown fallback reason", recorded: cmpv1alpha1.TransactionOperationIR, reason: "Revoked", operation: cmpv1alpha1.TransactionOperationKUR, fallback: cmpv1alpha1.TransactionOperationIR, failure: testFallbackNotAllowed},
		{name: "a renewal IR without a reason", recorded: cmpv1alpha1.TransactionOperationIR, operation: cmpv1alpha1.TransactionOperationKUR, fallback: cmpv1alpha1.TransactionOperationIR, failure: "different enrollment operation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction := &cmpv1alpha1.CMPTransaction{Spec: cmpv1alpha1.CMPTransactionSpec{CSRDigest: "digest", ConfigurationDigest: "configuration", IssuerRef: &issuerRef, Operation: test.recorded, RenewalFallback: test.reason}}
			err := validateResumedTransaction(transaction, "digest", test.operation, test.fallback, issuerRef)
			if test.failure == "" {
				if err != nil {
					t.Fatalf("expected the recorded transaction to be accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.failure) {
				t.Fatalf("expected a failure containing %q, got %v", test.failure, err)
			}
		})
	}
}

// TestLoadIRMaterialForRenewal verifies IR for a later revision needs a fallback reason, an issuer
// that falls back to IR and the owner-chain checks KUR uses.
func TestLoadIRMaterialForRenewal(t *testing.T) {
	for _, test := range []struct {
		name    string
		reason  string
		mutate  func(f *renewalFallbackFixture)
		failure string
	}{
		{name: "a fallback reason authorizes the second revision", reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing},
		{name: "no reason keeps IR on the first revision", failure: "IR requires the first certificate revision"},
		{name: "an issuer without the fallback refuses", reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, failure: "issuer does not fall back from KUR to IR", mutate: func(f *renewalFallbackFixture) {
			f.issuer.Spec.Protocol.RenewalFallback = cmpv1alpha1.RenewalFallbackNone
		}},
		{name: "a first revision refuses a fallback reason", reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, failure: "IR renewal requires a certificate revision greater than one", mutate: func(f *renewalFallbackFixture) {
			f.request.Annotations[certmanagerv1.CertificateRequestRevisionAnnotationKey] = "1"
			f.certificate.Status.Revision = nil
		}},
		{name: "a skipped revision refuses", reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, failure: testNotNextRevision, mutate: func(f *renewalFallbackFixture) {
			f.request.Annotations[certmanagerv1.CertificateRequestRevisionAnnotationKey] = "3"
		}},
		{name: "an unrecorded staged key refuses", reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, failure: testIRStagedKeyAuthorization, mutate: func(f *renewalFallbackFixture) {
			f.request.Annotations[certmanagerv1.CertificateRequestPrivateKeyAnnotationKey] = testUnrelatedPrivateKeySecret
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRenewalFallbackFixture(t)
			f.current = nil
			if test.mutate != nil {
				test.mutate(f)
			}
			kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(f.objects(t)...).Build()
			signer := &Signer{KubeClient: kubeClient}
			csrDER, err := protocol.ParseCertificateRequestDER(f.request.details.CSR)
			if err != nil {
				t.Fatal(err)
			}
			material, configurationErr := signer.loadIRMaterial(context.Background(), f.request, f.issuer, csrDER, test.reason)
			if test.failure != "" {
				if configurationErr == nil || !configurationErr.Permanent || !strings.Contains(configurationErr.Error(), test.failure) {
					t.Fatalf("expected a permanent failure containing %q, got %v", test.failure, configurationErr)
				}
				return
			}
			if configurationErr != nil {
				t.Fatalf("load IR material: %v", configurationErr)
			}
			if material.Protection != nil || material.RequestedPrivateKey == nil || len(material.Secrets) != 1 {
				t.Fatalf("expected only the staged key under the issuer protection, got %+v", material)
			}
		})
	}
}

// TestRenewalFallbackAgainstAPIServer verifies the fallback is recorded through the CMPTransaction
// schema of the API server. The envtest API server serves only the cmp-issuer CRDs, so the
// cert-manager objects and Secrets are read from a fake client.
func TestRenewalFallbackAgainstAPIServer(t *testing.T) {
	kube := startEnvtest(t)
	ctx := context.Background()
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testIssuerNamespace}}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	now := time.Now()
	for i, test := range []struct {
		name      string
		mutate    func(t *testing.T, f *renewalFallbackFixture)
		operation string
		reason    string
	}{
		{name: "a deleted Secret records IR", operation: cmpv1alpha1.TransactionOperationIR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current = nil
		}},
		{name: "an expired certificate records IR", operation: cmpv1alpha1.TransactionOperationIR, reason: cmpv1alpha1.RenewalFallbackCurrentCertificateExpired, mutate: func(t *testing.T, f *renewalFallbackFixture) {
			f.current.Data[corev1.TLSCertKey] = testCertificateWithValidity(t, f.currentKey, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}},
		{name: "a Secret of another Certificate records nothing", mutate: func(_ *testing.T, f *renewalFallbackFixture) {
			f.current.Annotations[certmanagerv1.CertificateNameKey] = testForeignCertificateName
			delete(f.current.Data, corev1.TLSCertKey)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRenewalFallbackFixture(t)
			test.mutate(t, f)
			// Each case records its transaction under its own request name.
			f.request.Name = fmt.Sprintf("%s-%d", testRequestName, i)
			reader := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(f.objects(t)...).Build()
			issued := issuedCertificateFor(t, f.request.details.CSR)
			protocolClient := &fakeProtocolClient{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}
			signer := &Signer{KubeClient: reader, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: &transactionStore{reader: kube, writer: kube}}
			_, err := signer.Sign(ctx, f.request, f.issuer)
			stored := &cmpv1alpha1.CMPTransaction{}
			readErr := kube.Get(ctx, types.NamespacedName{Namespace: testIssuerNamespace, Name: f.request.Name}, stored)
			if test.operation == "" {
				var permanent issuersigner.PermanentError
				if !errors.As(err, &permanent) || !apierrors.IsNotFound(readErr) {
					t.Fatalf("expected a permanent failure and no transaction, got %v and %v", err, readErr)
				}
				return
			}
			if err != nil || readErr != nil {
				t.Fatalf("expected a recorded fallback, got %v and %v", err, readErr)
			}
			if stored.Spec.Operation != test.operation || stored.Spec.RenewalFallback != test.reason || stored.Status.Phase != cmpv1alpha1.TransactionPhaseIssued {
				t.Fatalf("expected an issued %s transaction with fallback %s, got %s, %q and %s", test.operation, test.reason, stored.Spec.Operation, stored.Spec.RenewalFallback, stored.Status.Phase)
			}
		})
	}
}
