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
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
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
	issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: validSpec("https://example.test/cmp")}
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
	if fixture.transaction(t) != nil {
		t.Fatal("expected the completed transaction state to be removed")
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
		{err: &protocol.Error{Kind: protocol.ErrorKindRetryable, Operation: "HTTP exchange", Failure: "systemUnavail", Err: errors.New("connection refused")}},
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
		{err: &protocol.Error{Kind: protocol.ErrorKindPermanent, Operation: "process PKIStatus", Failure: "badRequest", Err: errors.New("rejected")}},
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
