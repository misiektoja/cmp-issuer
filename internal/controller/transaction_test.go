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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

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

const testRequestName = "request"

// testCMPFailure is the CMP failure name the rejection fixtures report.
const testCMPFailure = "badRequest"

// testCMPOperation is the protocol step the rejection fixtures report the failure against.
const testCMPOperation = "process PKIStatus"
const testRequestUID = types.UID("11111111-1111-1111-1111-111111111111")

// asyncFixture holds the collaborators of one asynchronous transaction test.
type asyncFixture struct {
	signer   *Signer
	issuer   *cmpv1alpha1.CMPIssuer
	request  *fakeCertificateRequest
	protocol *fakeProtocolClient
	kube     client.Client
	leaf     *x509.Certificate
}

// newAsyncFixture builds a signer whose protocol client returns the queued exchanges in order.
func newAsyncFixture(t *testing.T, queue []fakeExchange) *asyncFixture {
	t.Helper()
	auth, trust, leaf := credentialSecrets(t, testIssuerNamespace)
	kubeClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust).WithStatusSubresource(&cmpv1alpha1.CMPTransaction{}).Build()
	protocolClient := &fakeProtocolClient{queue: queue}
	signer := &Signer{KubeClient: kubeClient, ProtocolClient: protocolClient, EventRecorder: events.NewFakeRecorder(10), ClusterResourceNamespace: testClusterResourceNamespace, transactions: testTransactions(kubeClient)}
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace, UID: types.UID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), Generation: 3}, Spec: validSpec("https://example.test/cmp")}
	request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testIssuerNamespace, UID: testRequestUID}, details: issuersigner.CertificateDetails{CSR: testCSR(t)}}
	return &asyncFixture{signer: signer, issuer: issuer, request: request, protocol: protocolClient, kube: kubeClient, leaf: leaf}
}

// sign runs one reconcile of the signer against the fixture.
func (f *asyncFixture) sign(t *testing.T) (issuersigner.PEMBundle, error) {
	t.Helper()
	return f.signer.Sign(context.Background(), f.request, f.issuer)
}

// transaction reads the stored transaction state, or nil when none is recorded.
func (f *asyncFixture) transaction(t *testing.T) *cmpv1alpha1.CMPTransaction {
	t.Helper()
	stored := &cmpv1alpha1.CMPTransaction{}
	err := f.kube.Get(context.Background(), types.NamespacedName{Namespace: testIssuerNamespace, Name: testRequestName}, stored)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read transaction state: %v", err)
	}
	return stored
}

// waitingResult returns an enrollment outcome that reports a server-side waiting status.
func waitingResult(certReqID int64, nonce string, checkAfter time.Duration) protocol.EnrollmentResult {
	return protocol.EnrollmentResult{Pending: &protocol.PendingTransaction{CertReqID: certReqID, RecipNonce: []byte(nonce), CheckAfter: checkAfter, RequestNonce: []byte("request-nonce")}}
}

// requirePending asserts that a Sign call asked for another reconcile after the expected delay.
func requirePending(t *testing.T, err error, expected time.Duration) {
	t.Helper()
	var pending issuersigner.PendingError
	if !errors.As(err, &pending) {
		t.Fatalf("expected a pending error, got %v", err)
	}
	if pending.RequeueAfter != expected {
		t.Fatalf("expected requeue after %s, got %s", expected, pending.RequeueAfter)
	}
}

// TestSignPersistsTransactionBeforeEnrolling verifies the transaction ID is recorded and reused.
func TestSignPersistsTransactionBeforeEnrolling(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce-one", 0)}})
	_, err := fixture.sign(t)
	requirePending(t, err, time.Second)
	stored := fixture.transaction(t)
	if stored == nil {
		t.Fatal("expected the waiting transaction to be recorded")
	}
	if len(stored.Spec.TransactionID) != transactionIDLength {
		t.Fatalf("expected a %d byte transaction ID, got %d", transactionIDLength, len(stored.Spec.TransactionID))
	}
	if !bytes.Equal(fixture.protocol.request.TransactionID, stored.Spec.TransactionID) {
		t.Fatal("the enrollment did not carry the recorded transaction ID")
	}
	if stored.Spec.CertificateRequestUID != string(testRequestUID) {
		t.Fatalf("expected the request UID to be recorded, got %q", stored.Spec.CertificateRequestUID)
	}
	if stored.Status.Phase != cmpv1alpha1.TransactionPhasePolling {
		t.Fatalf("expected the polling phase, got %q", stored.Status.Phase)
	}
	if stored.Status.CertReqID == nil || *stored.Status.CertReqID != 0 {
		t.Fatalf("expected the polled certReqId to be recorded, got %v", stored.Status.CertReqID)
	}
	if len(stored.OwnerReferences) != 1 || stored.OwnerReferences[0].UID != testRequestUID {
		t.Fatalf("expected an owner reference to the CertificateRequest, got %v", stored.OwnerReferences)
	}
}

// TestSignPollsRecordedTransactionUntilIssued verifies a waiting transaction is resumed by polling.
func TestSignPollsRecordedTransactionUntilIssued(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{
		{result: waitingResult(protocol.ResponseCertReqIDStandard, "nonce-one", 0)},
		{result: waitingResult(protocol.ResponseCertReqIDStandard, "nonce-two", 30*time.Second)},
	})
	_, err := fixture.sign(t)
	requirePending(t, err, time.Second)
	recorded := fixture.transaction(t)

	_, err = fixture.sign(t)
	requirePending(t, err, 30*time.Second)
	if fixture.protocol.calls != 1 || fixture.protocol.polls != 1 {
		t.Fatalf("expected one enrollment and one poll, got %d and %d", fixture.protocol.calls, fixture.protocol.polls)
	}
	if !bytes.Equal(fixture.protocol.pollRequest.Enrollment.TransactionID, recorded.Spec.TransactionID) {
		t.Fatal("the poll did not reuse the recorded transaction ID")
	}
	if string(fixture.protocol.pollRequest.RecipNonce) != "nonce-one" {
		t.Fatalf("expected the poll to echo the recorded nonce, got %q", fixture.protocol.pollRequest.RecipNonce)
	}
	if fixture.protocol.pollRequest.CertReqID != protocol.ResponseCertReqIDStandard {
		t.Fatalf("expected the poll to carry the recorded certReqId, got %d", fixture.protocol.pollRequest.CertReqID)
	}
	if string(fixture.protocol.pollRequest.RequestNonce) != "request-nonce" {
		t.Fatalf("expected the poll to carry the recorded request nonce, got %q", fixture.protocol.pollRequest.RequestNonce)
	}
	stored := fixture.transaction(t)
	if string(stored.Status.RequestNonce) != "request-nonce" {
		t.Fatalf("expected the delayed request nonce to be persisted, got %q", stored.Status.RequestNonce)
	}
	if string(stored.Status.RecipNonce) != "nonce-two" {
		t.Fatalf("expected the nonce to advance, got %q", stored.Status.RecipNonce)
	}
	if stored.Status.Polls != 1 {
		t.Fatalf("expected exactly the one sent poll to be counted, got %d", stored.Status.Polls)
	}

	fixture.protocol.queue = []fakeExchange{{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{fixture.leaf}}}}
	bundle, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("expected the poll to complete the transaction, got %v", err)
	}
	if len(bundle.ChainPEM) == 0 {
		t.Fatal("expected an issued chain")
	}
	completed := fixture.transaction(t)
	if completed == nil || completed.Status.Phase != cmpv1alpha1.TransactionPhaseIssued {
		t.Fatalf("expected the completed transaction to record the issued phase, got %v", completed)
	}
	if len(completed.Status.IssuedChain) != 1 || !bytes.Equal(completed.Status.IssuedChain[0], fixture.leaf.Raw) {
		t.Fatal("expected the validated chain to be recorded before it was returned")
	}
	if completed.Status.CompletionTime.IsZero() {
		t.Fatal("expected the completion time to be recorded")
	}
}

// TestSignRecordsTransactionDetail verifies a transaction describes the request it enrolls.
func TestSignRecordsTransactionDetail(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the exchange to report waiting")
	}
	stored := fixture.transaction(t)
	digest := sha256.Sum256(fixture.protocol.request.CSRDER)
	if stored.Spec.CSRDigest != hex.EncodeToString(digest[:]) {
		t.Fatalf("expected the CSR digest to be recorded, got %q", stored.Spec.CSRDigest)
	}
	if stored.Spec.IssuerRef == nil || stored.Spec.IssuerRef.Name != testIssuerName || stored.Spec.IssuerRef.Kind != cmpv1alpha1.TransactionIssuerKindNamespaced {
		t.Fatalf("expected the issuer reference to be recorded, got %v", stored.Spec.IssuerRef)
	}
	if stored.Spec.IssuerRef.UID != string(fixture.issuer.UID) || stored.Spec.IssuerRef.Generation != fixture.issuer.Generation {
		t.Fatalf("expected issuer identity and generation to be recorded, got %v", stored.Spec.IssuerRef)
	}
	if len(stored.Spec.ConfigurationDigest) != sha256.Size*2 {
		t.Fatalf("expected the credential configuration digest to be recorded, got %q", stored.Spec.ConfigurationDigest)
	}
	if stored.Spec.Operation != cmpv1alpha1.TransactionOperationP10CR {
		t.Fatalf("expected the CMP operation to be recorded, got %q", stored.Spec.Operation)
	}
	if stored.Spec.ProtocolVersion != cmpProtocolVersion {
		t.Fatalf("expected the protocol version to be recorded, got %d", stored.Spec.ProtocolVersion)
	}
}

// TestSignReusesThePinnedTransactionAfterInterruption verifies a retry that follows an interrupted
// attempt enrolls under the transaction identifier already recorded, rather than a fresh one. A new
// identifier would present the retry to the server as a separate enrollment and earn a second
// certificate for a request that may already have been answered.
func TestSignReusesThePinnedTransactionAfterInterruption(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{
		{err: &protocol.Error{Kind: protocol.ErrorKindRetryable, Operation: testHTTPExchangeOperation, Failure: testFailureSystemUnavailable, Err: errors.New("connection reset")}},
		{result: waitingResult(0, "nonce", 0)},
	})
	requirePending(t, mustFail(fixture.sign(t)), time.Second)
	recorded := fixture.transaction(t)
	if len(recorded.Spec.TransactionID) == 0 {
		t.Fatal("expected the transaction identifier to be pinned before the message was sent")
	}
	if !bytes.Equal(fixture.protocol.request.TransactionID, recorded.Spec.TransactionID) {
		t.Fatal("expected the first attempt to enroll under the pinned transaction identifier")
	}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the retry to report waiting")
	}
	if !bytes.Equal(fixture.protocol.request.TransactionID, recorded.Spec.TransactionID) {
		t.Fatal("expected the retry to reuse the pinned transaction identifier")
	}
	if retried := fixture.transaction(t); !bytes.Equal(retried.Spec.TransactionID, recorded.Spec.TransactionID) {
		t.Fatal("expected the recorded transaction identifier to be unchanged by the retry")
	}
}

// issuedCertificateFor mints a certificate carrying the public key of a CSR, as a CMP server would,
// so that a recorded chain can be checked against the request it belongs to.
func issuedCertificateFor(t *testing.T, csrPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("expected the fixture CSR to be PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse the fixture CSR: %v", err)
	}
	issuingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate an issuing key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, issuingKey)
	if err != nil {
		t.Fatalf("issue the fixture certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse the issued fixture certificate: %v", err)
	}
	return certificate
}

// TestSignReturnsRecordedChainAfterRestart verifies an issued transaction is not enrolled again.
func TestSignReturnsRecordedChainAfterRestart(t *testing.T) {
	fixture := newAsyncFixture(t, nil)
	issued := issuedCertificateFor(t, fixture.request.details.CSR)
	fixture.protocol.queue = []fakeExchange{{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}}
	bundle, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("expected the enrollment to complete, got %v", err)
	}
	replayed, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("expected the recorded chain to be returned, got %v", err)
	}
	if !bytes.Equal(bundle.ChainPEM, replayed.ChainPEM) {
		t.Fatal("expected the recorded chain to match the originally issued chain")
	}
	if fixture.protocol.calls != 1 || fixture.protocol.polls != 0 {
		t.Fatalf("expected no further CMP traffic, got %d enrollments and %d polls", fixture.protocol.calls, fixture.protocol.polls)
	}
}

// confirmingResult returns an enrollment outcome whose certificate is issued but not yet confirmed.
func confirmingResult(issued *x509.Certificate, nonce string) protocol.EnrollmentResult {
	return protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}, PendingConfirmation: &protocol.PendingTransaction{CertReqID: protocol.ResponseCertReqIDStandard, RecipNonce: []byte(nonce)}}
}

// TestSignRecordsTheChainBeforeConfirming verifies the certificate is durable before certConf is
// sent, which is what allows an interrupted confirmation to resume rather than lose a certificate.
func TestSignRecordsTheChainBeforeConfirming(t *testing.T) {
	fixture := newAsyncFixture(t, nil)
	issued := issuedCertificateFor(t, fixture.request.details.CSR)
	fixture.protocol.queue = []fakeExchange{
		{result: confirmingResult(issued, "confirm-nonce")},
		{result: protocol.EnrollmentResult{ExplicitConfirmation: true}},
	}
	bundle, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("expected the enrollment to complete, got %v", err)
	}
	if fixture.protocol.confirms != 1 {
		t.Fatalf("expected exactly one confirmation, got %d", fixture.protocol.confirms)
	}
	if fixture.protocol.confirmRequest.Certificate == nil || !fixture.protocol.confirmRequest.Certificate.Equal(issued) {
		t.Fatal("expected the confirmation to name the issued certificate")
	}
	if len(fixture.protocol.confirmRequest.RequestNonce) != 0 {
		t.Fatal("expected the first confirmation to send certConf rather than a poll")
	}
	completed := fixture.transaction(t)
	if completed.Status.Phase != cmpv1alpha1.TransactionPhaseIssued {
		t.Fatalf("expected the issued phase after confirmation, got %q", completed.Status.Phase)
	}
	if len(bundle.ChainPEM) == 0 {
		t.Fatal("expected the confirmed chain to be returned")
	}
}

// TestSignResumesADelayedConfirmationAfterRestart verifies a certificate whose confirmation the
// server delayed is confirmed on a later reconcile instead of being enrolled again or discarded.
func TestSignResumesADelayedConfirmationAfterRestart(t *testing.T) {
	fixture := newAsyncFixture(t, nil)
	fixture.issuer.Spec.Transaction.MaximumPolls = 1
	issued := issuedCertificateFor(t, fixture.request.details.CSR)
	fixture.protocol.queue = []fakeExchange{
		{result: confirmingResult(issued, "confirm-nonce")},
		{result: protocol.EnrollmentResult{PendingConfirmation: &protocol.PendingTransaction{CertReqID: protocol.ResponseCertReqIDStandard, RecipNonce: []byte("delayed-nonce"), RequestNonce: []byte("certconf-nonce"), CheckAfter: 2 * time.Second}}},
		{result: protocol.EnrollmentResult{ExplicitConfirmation: true}},
	}
	requirePending(t, mustFail(fixture.sign(t)), 2*time.Second)

	recorded := fixture.transaction(t)
	if recorded.Status.Phase != cmpv1alpha1.TransactionPhaseConfirming {
		t.Fatalf("expected the confirming phase, got %q", recorded.Status.Phase)
	}
	if len(recorded.Status.IssuedChain) != 1 {
		t.Fatalf("expected the chain to be recorded before confirmation, got %d certificates", len(recorded.Status.IssuedChain))
	}
	if recorded.Status.Polls != 0 {
		t.Fatalf("expected certConf not to consume the pollReq budget, got %d polls", recorded.Status.Polls)
	}

	bundle, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("expected the resumed confirmation to complete, got %v", err)
	}
	if fixture.protocol.calls != 1 {
		t.Fatalf("expected no second enrollment, got %d", fixture.protocol.calls)
	}
	if string(fixture.protocol.confirmRequest.RequestNonce) != "certconf-nonce" {
		t.Fatalf("expected the resumed confirmation to poll with the recorded certConf nonce, got %q", fixture.protocol.confirmRequest.RequestNonce)
	}
	if len(bundle.ChainPEM) == 0 {
		t.Fatal("expected the confirmed chain to be returned")
	}
	if fixture.transaction(t).Status.Phase != cmpv1alpha1.TransactionPhaseIssued {
		t.Fatal("expected the resumed transaction to reach the issued phase")
	}
}

// TestSignResendsCertConfAfterADelayedEnrollment verifies an interrupted confirmation of a delayed
// enrollment resends certConf instead of polling for a certConf that was never sent.
func TestSignResendsCertConfAfterADelayedEnrollment(t *testing.T) {
	fixture := newAsyncFixture(t, nil)
	issued := issuedCertificateFor(t, fixture.request.details.CSR)
	fixture.protocol.queue = []fakeExchange{
		{result: waitingResult(protocol.ResponseCertReqIDStandard, "nonce-one", 0)},
		{result: confirmingResult(issued, "confirm-nonce")},
		{err: &protocol.Error{Kind: protocol.ErrorKindRetryable, Operation: "HTTP exchange", Failure: "systemUnavail"}},
		{result: protocol.EnrollmentResult{ExplicitConfirmation: true}},
	}

	requirePending(t, mustFail(fixture.sign(t)), time.Second)
	if stored := fixture.transaction(t); string(stored.Status.RequestNonce) != "request-nonce" {
		t.Fatalf("expected the delayed enrollment nonce to be recorded while polling, got %q", stored.Status.RequestNonce)
	}

	// The poll returns the issued certificate and the certConf that follows fails retryably, which
	// leaves the transaction in the Confirming phase with certConf still unsent.
	requirePending(t, mustFail(fixture.sign(t)), time.Second)
	recorded := fixture.transaction(t)
	if recorded == nil || recorded.Status.Phase != cmpv1alpha1.TransactionPhaseConfirming {
		t.Fatalf("expected the confirming phase after the interrupted certConf, got %v", recorded)
	}
	if len(recorded.Status.RequestNonce) != 0 {
		t.Fatalf("expected the enrollment nonce to be cleared when confirmation began, got %q", recorded.Status.RequestNonce)
	}

	bundle, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("expected the resumed confirmation to complete, got %v", err)
	}
	if fixture.protocol.confirms != 2 {
		t.Fatalf("expected certConf to be sent again, got %d confirmations", fixture.protocol.confirms)
	}
	if nonce := fixture.protocol.confirmRequest.RequestNonce; len(nonce) != 0 {
		t.Fatalf("expected the resumed confirmation to resend certConf rather than poll, got request nonce %q", nonce)
	}
	if len(bundle.ChainPEM) == 0 {
		t.Fatal("expected the confirmed chain to be returned")
	}
}

// TestSignRejectsTransactionFromRecreatedIssuer verifies a reused issuer name cannot resume an old transaction.
func TestSignRejectsTransactionFromRecreatedIssuer(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the first exchange to report waiting")
	}
	fixture.issuer.UID = types.UID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent issuer identity mismatch, got %v", err)
	}
	if fixture.protocol.polls != 0 {
		t.Fatal("expected no CMP poll after issuer recreation")
	}
}

// TestSignRejectsIssuerSpecChangeDuringTransaction verifies a new issuer generation cannot resume old state.
func TestSignRejectsIssuerSpecChangeDuringTransaction(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the first exchange to report waiting")
	}
	fixture.issuer.Generation++
	fixture.issuer.Spec.Endpoint.URL = "https://different.example.test/cmp"
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent issuer generation mismatch, got %v", err)
	}
	if fixture.protocol.polls != 0 {
		t.Fatal("expected no CMP poll after issuer spec change")
	}
}

// TestSignRejectsCredentialRotationDuringTransaction verifies an open transaction cannot change protection material.
func TestSignRejectsCredentialRotationDuringTransaction(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the first exchange to report waiting")
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: testIssuerNamespace, Name: testAuthSecretName}
	if err := fixture.kube.Get(context.Background(), key, secret); err != nil {
		t.Fatalf("read credential Secret: %v", err)
	}
	secret.Data["secret"] = []byte("rotated-shared-secret")
	if err := fixture.kube.Update(context.Background(), secret); err != nil {
		t.Fatalf("rotate credential Secret: %v", err)
	}
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent credential continuity failure, got %v", err)
	}
	if fixture.protocol.polls != 0 {
		t.Fatal("expected no CMP poll with rotated credentials")
	}
}

// TestSignRecoversIssuedChainWithoutCredentials verifies durable issuance does not depend on live Secrets.
func TestSignRecoversIssuedChainWithoutCredentials(t *testing.T) {
	fixture := newAsyncFixture(t, nil)
	issued := issuedCertificateFor(t, fixture.request.details.CSR)
	fixture.protocol.queue = []fakeExchange{{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issued}}}}
	want, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("complete enrollment: %v", err)
	}
	for _, name := range []string{testAuthSecretName, testTrustSecretName} {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testIssuerNamespace}}
		if err := fixture.kube.Delete(context.Background(), secret); err != nil {
			t.Fatalf("delete fixture Secret %s: %v", name, err)
		}
	}
	fixture.issuer.Generation++
	fixture.issuer.Spec.Endpoint.URL = "not a valid endpoint"
	got, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("recover issued chain without credentials: %v", err)
	}
	if !bytes.Equal(got.ChainPEM, want.ChainPEM) {
		t.Fatal("expected the recovered chain to match the issued chain")
	}
}

// mustFail returns the error of a Sign call that was expected not to complete.
func mustFail(_ issuersigner.PEMBundle, err error) error { return err }

// TestSignRejectsRecordedTransactionForADifferentCSR verifies a mismatched record is not resumed.
func TestSignRejectsRecordedTransactionForADifferentCSR(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the exchange to report waiting")
	}
	stored := fixture.transaction(t)
	stored.Spec.CSRDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := fixture.kube.Update(context.Background(), stored); err != nil {
		t.Fatalf("rewrite the recorded CSR digest: %v", err)
	}
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent mismatch failure, got %v", err)
	}
	if fixture.protocol.polls != 0 {
		t.Fatal("expected no poll to be sent for a mismatched transaction")
	}
}

// TestSignRetainsResponseSignerAcrossPolls verifies the validated signer survives a restart.
func TestSignRetainsResponseSignerAcrossPolls(t *testing.T) {
	fixture := newAsyncFixture(t, nil)
	pending := waitingResult(0, "nonce-one", 0)
	pending.Pending.ResponseSigner = fixture.leaf
	fixture.protocol.queue = []fakeExchange{{result: pending}, {result: waitingResult(0, "nonce-two", 0)}}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the first exchange to report waiting")
	}
	stored := fixture.transaction(t)
	if !bytes.Equal(stored.Status.ResponseSigner, fixture.leaf.Raw) {
		t.Fatal("expected the validated response signer to be retained")
	}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the poll to report waiting")
	}
	if fixture.protocol.pollRequest.ResponseSigner == nil || !fixture.protocol.pollRequest.ResponseSigner.Equal(fixture.leaf) {
		t.Fatal("expected the retained signer to be supplied to the poll")
	}
}

// TestSignClampsServerCheckAfterToConfiguredBounds verifies polling honors the issuer limits.
func TestSignClampsServerCheckAfterToConfiguredBounds(t *testing.T) {
	for name, testCase := range map[string]struct {
		checkAfter time.Duration
		minimum    time.Duration
		maximum    time.Duration
		expected   time.Duration
	}{
		"below the minimum":  {checkAfter: time.Millisecond, minimum: 5 * time.Second, maximum: time.Minute, expected: 5 * time.Second},
		"within the bounds":  {checkAfter: 20 * time.Second, minimum: 5 * time.Second, maximum: time.Minute, expected: 20 * time.Second},
		"above the maximum":  {checkAfter: time.Hour, minimum: 5 * time.Second, maximum: time.Minute, expected: time.Minute},
		"absent from server": {checkAfter: 0, minimum: 5 * time.Second, maximum: time.Minute, expected: 5 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", testCase.checkAfter)}})
			fixture.issuer.Spec.Transaction = cmpv1alpha1.TransactionSpec{
				MaximumDuration:     metav1.Duration{Duration: time.Hour},
				MinimumPollInterval: metav1.Duration{Duration: testCase.minimum},
				MaximumPollInterval: metav1.Duration{Duration: testCase.maximum},
				MaximumPolls:        60,
			}
			_, err := fixture.sign(t)
			requirePending(t, err, testCase.expected)
		})
	}
}

// TestSignFailsWhenTransactionDeadlinePasses verifies a stalled transaction ends and is cleaned up.
func TestSignFailsWhenTransactionDeadlinePasses(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
	fixture.issuer.Spec.Transaction = cmpv1alpha1.TransactionSpec{
		MaximumDuration:     metav1.Duration{Duration: time.Millisecond},
		MinimumPollInterval: metav1.Duration{Duration: time.Millisecond},
		MaximumPollInterval: metav1.Duration{Duration: time.Second},
		MaximumPolls:        60,
	}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the first exchange to report waiting")
	}
	time.Sleep(5 * time.Millisecond)
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent deadline failure, got %v", err)
	}
	if fixture.protocol.polls != 0 {
		t.Fatal("expected no poll to be sent after the deadline")
	}
	if fixture.transaction(t) != nil {
		t.Fatal("expected the abandoned transaction state to be removed")
	}
}

// TestSignFailsWhenMaximumPollsReached verifies the configured poll budget bounds a transaction.
func TestSignFailsWhenMaximumPollsReached(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{
		{result: waitingResult(0, "nonce-one", 0)},
		{result: waitingResult(0, "nonce-two", 0)},
	})
	fixture.issuer.Spec.Transaction = cmpv1alpha1.TransactionSpec{
		MaximumDuration:     metav1.Duration{Duration: time.Hour},
		MinimumPollInterval: metav1.Duration{Duration: time.Millisecond},
		MaximumPollInterval: metav1.Duration{Duration: time.Second},
		MaximumPolls:        1,
	}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the first exchange to report waiting")
	}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the only permitted poll to report waiting")
	}
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent poll budget failure, got %v", err)
	}
	if fixture.protocol.polls != 1 {
		t.Fatalf("expected exactly the budgeted poll to be sent, got %d", fixture.protocol.polls)
	}
}

// TestSignDiscardsStateFromRecreatedRequest verifies a reused name does not resume a foreign transaction.
func TestSignDiscardsStateFromRecreatedRequest(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce-one", 0)}, {result: waitingResult(0, "nonce-two", 0)}})
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the first exchange to report waiting")
	}
	first := fixture.transaction(t)

	fixture.request.UID = types.UID("22222222-2222-2222-2222-222222222222")
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the recreated request to report waiting")
	}
	if fixture.protocol.polls != 0 {
		t.Fatal("expected the recreated request to enroll rather than poll")
	}
	second := fixture.transaction(t)
	if bytes.Equal(first.Spec.TransactionID, second.Spec.TransactionID) {
		t.Fatal("expected the recreated request to start a new transaction")
	}
	if second.Spec.CertificateRequestUID != string(fixture.request.UID) {
		t.Fatalf("expected the new request UID to be recorded, got %q", second.Spec.CertificateRequestUID)
	}
}

// TestSignRetriesEnrollmentUnderTheRecordedTransactionID verifies an interrupted send is not duplicated.
func TestSignRetriesEnrollmentUnderTheRecordedTransactionID(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{
		{err: &protocol.Error{Kind: protocol.ErrorKindRetryable, Operation: testHTTPExchangeOperation, Failure: testFailureSystemUnavailable, Err: errors.New("connection refused")}},
		{result: waitingResult(0, "nonce", 0)},
	})
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the transport failure to surface")
	}
	recorded := fixture.transaction(t)
	if recorded == nil {
		t.Fatal("expected the transaction to survive a retryable failure")
	}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected the retry to report waiting")
	}
	if fixture.protocol.calls != 2 || fixture.protocol.polls != 0 {
		t.Fatalf("expected the enrollment to be retried, got %d enrollments and %d polls", fixture.protocol.calls, fixture.protocol.polls)
	}
	if !bytes.Equal(fixture.protocol.request.TransactionID, recorded.Spec.TransactionID) {
		t.Fatal("expected the retry to reuse the recorded transaction ID")
	}
}

// TestSignRemovesStateOnPermanentFailure verifies a rejected transaction leaves no stale state.
func TestSignRemovesStateOnPermanentFailure(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{
		{err: &protocol.Error{Kind: protocol.ErrorKindPermanent, Operation: testCMPOperation, Failure: testCMPFailure, Err: errors.New("rejected")}},
	})
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("expected a permanent failure, got %v", err)
	}
	if fixture.transaction(t) != nil {
		t.Fatal("expected the rejected transaction state to be removed")
	}
}
