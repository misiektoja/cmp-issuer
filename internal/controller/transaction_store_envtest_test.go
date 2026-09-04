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
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// startEnvtest boots an API server with the project CRDs, or skips when its binaries are absent.
func startEnvtest(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is unset, run this test through make test")
	}
	environment := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true}
	configuration, err := environment.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := environment.Stop(); stopErr != nil {
			t.Errorf("stop envtest: %v", stopErr)
		}
	})
	kubeClient, err := client.New(configuration, client.Options{Scheme: testScheme(t)})
	if err != nil {
		t.Fatalf("create envtest client: %v", err)
	}
	return kubeClient
}

// testTransactionDetail returns the recorded description of an enrolled request for store tests.
func testTransactionDetail() transactionDetail {
	return transactionDetail{
		CSRDigest:       "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
		IssuerRef:       cmpv1alpha1.TransactionIssuerReference{Name: testIssuerName, Kind: cmpv1alpha1.TransactionIssuerKindNamespaced, UID: "33333333-3333-3333-3333-333333333333"},
		Operation:       cmpv1alpha1.TransactionOperationP10CR,
		ProtocolVersion: cmpProtocolVersion,
	}
}

// TestTransactionStoreAgainstAPIServer verifies the recorded state round-trips through a real API server.
func TestTransactionStoreAgainstAPIServer(t *testing.T) {
	kubeClient := startEnvtest(t)
	ctx := context.Background()
	namespace := "cmp-transaction-store"
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	store := &transactionStore{reader: kubeClient, writer: kubeClient}

	if loaded, err := store.load(ctx, namespace, testRequestName, testRequestUID); err != nil || loaded != nil {
		t.Fatalf("expected no recorded transaction, got %v and %v", loaded, err)
	}

	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	created, err := store.create(ctx, namespace, testRequestName, testRequestUID, deadline, testTransactionDetail())
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if created.Status.Phase != cmpv1alpha1.TransactionPhaseEnrolling {
		t.Fatalf("expected the enrolling phase to be accepted, got %q", created.Status.Phase)
	}

	loaded, err := store.load(ctx, namespace, testRequestName, testRequestUID)
	if err != nil || loaded == nil {
		t.Fatalf("expected the recorded transaction, got %v and %v", loaded, err)
	}
	if !bytes.Equal(loaded.Spec.TransactionID, created.Spec.TransactionID) {
		t.Fatal("the transaction ID did not survive the API server round trip")
	}
	if !loaded.Spec.Deadline.Time.Equal(deadline) {
		t.Fatalf("expected the deadline %s, got %s", deadline, loaded.Spec.Deadline.Time)
	}
	_, _, signer := credentialSecrets(t, namespace)
	pending := &protocol.PendingTransaction{CertReqID: protocol.ResponseCertReqIDStandard, RecipNonce: []byte{1, 2, 3, 4}, ResponseSigner: signer, RequestNonce: []byte{5, 6, 7, 8}}
	if err := store.recordPending(ctx, loaded, pending); err != nil {
		t.Fatalf("record pending state: %v", err)
	}
	polled, err := store.load(ctx, namespace, testRequestName, testRequestUID)
	if err != nil || polled == nil {
		t.Fatalf("expected the polling transaction, got %v and %v", polled, err)
	}
	if polled.Status.Phase != cmpv1alpha1.TransactionPhasePolling {
		t.Fatalf("expected the polling phase, got %q", polled.Status.Phase)
	}
	if polled.Status.CertReqID == nil || *polled.Status.CertReqID != protocol.ResponseCertReqIDStandard {
		t.Fatalf("expected the negative certReqId to be stored, got %v", polled.Status.CertReqID)
	}
	if !bytes.Equal(polled.Status.RecipNonce, pending.RecipNonce) {
		t.Fatal("the recipient nonce did not survive the API server round trip")
	}
	if !bytes.Equal(polled.Status.RequestNonce, pending.RequestNonce) {
		t.Fatal("the delayed request nonce did not survive the API server round trip")
	}
	if !bytes.Equal(polled.Status.ResponseSigner, signer.Raw) {
		t.Fatal("the retained response signer did not survive the API server round trip")
	}

	if err := store.remove(ctx, polled); err != nil {
		t.Fatalf("remove transaction: %v", err)
	}
	if err := store.remove(ctx, polled); err != nil {
		t.Fatalf("expected removing an absent transaction to succeed, got %v", err)
	}
	if loaded, err := store.load(ctx, namespace, testRequestName, testRequestUID); err != nil || loaded != nil {
		t.Fatalf("expected the removed transaction to be absent, got %v and %v", loaded, err)
	}
}

// TestTransactionDurabilityAgainstAPIServer verifies the transaction detail and issued chain
// round-trip through a real API server and are cleared when they expire.
func TestTransactionDurabilityAgainstAPIServer(t *testing.T) {
	kubeClient := startEnvtest(t)
	ctx := context.Background()
	namespace := "cmp-transaction-durability"
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	store := &transactionStore{reader: kubeClient, writer: kubeClient}
	detail := testTransactionDetail()
	transaction, err := store.create(ctx, namespace, testRequestName, testRequestUID, time.Now().Add(time.Hour), detail)
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if transaction.Spec.CSRDigest != detail.CSRDigest || transaction.Spec.Operation != detail.Operation || transaction.Spec.ProtocolVersion != detail.ProtocolVersion {
		t.Fatalf("the transaction detail was not accepted: %+v", transaction.Spec)
	}
	if transaction.Spec.IssuerRef == nil || *transaction.Spec.IssuerRef != detail.IssuerRef {
		t.Fatalf("the issuer reference was not accepted: %v", transaction.Spec.IssuerRef)
	}

	enrolling := mustLoad(t, ctx, store, namespace)
	if !bytes.Equal(enrolling.Spec.TransactionID, transaction.Spec.TransactionID) {
		t.Fatal("the pinned transaction identifier did not survive the API server round trip")
	}

	_, _, signer := credentialSecrets(t, namespace)
	if err := store.recordPending(ctx, enrolling, &protocol.PendingTransaction{CertReqID: protocol.ResponseCertReqIDStandard, RecipNonce: []byte{1, 2, 3, 4}}); err != nil {
		t.Fatalf("record pending state: %v", err)
	}
	polling := mustLoad(t, ctx, store, namespace)
	if polling.Status.Phase != cmpv1alpha1.TransactionPhasePolling {
		t.Fatalf("expected the polling phase to be accepted, got %q", polling.Status.Phase)
	}

	if err := store.recordIssued(ctx, polling, []*x509.Certificate{signer}); err != nil {
		t.Fatalf("record the issued chain: %v", err)
	}
	issued := mustLoad(t, ctx, store, namespace)
	if issued.Status.Phase != cmpv1alpha1.TransactionPhaseIssued {
		t.Fatalf("expected the issued phase to be accepted, got %q", issued.Status.Phase)
	}
	if len(issued.Status.IssuedChain) != 1 || !bytes.Equal(issued.Status.IssuedChain[0], signer.Raw) {
		t.Fatal("the issued chain did not survive the API server round trip")
	}
	if issued.Status.CompletionTime.IsZero() {
		t.Fatal("expected the completion time to survive the API server round trip")
	}
}

// mustLoad reads the recorded transaction of the test request, failing when it is absent.
func mustLoad(t *testing.T, ctx context.Context, store *transactionStore, namespace string) *cmpv1alpha1.CMPTransaction {
	t.Helper()
	loaded, err := store.load(ctx, namespace, testRequestName, testRequestUID)
	if err != nil || loaded == nil {
		t.Fatalf("expected the recorded transaction, got %v and %v", loaded, err)
	}
	return loaded
}

// TestTransactionStoreKeepsRecreatedStateAgainstAPIServer verifies the API server refuses to remove a
// transaction that was recreated under the same name after the record being removed was read.
func TestTransactionStoreKeepsRecreatedStateAgainstAPIServer(t *testing.T) {
	kubeClient := startEnvtest(t)
	ctx := context.Background()
	namespace := "cmp-transaction-recreated"
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	store := &transactionStore{reader: kubeClient, writer: kubeClient}
	completed, err := store.create(ctx, namespace, testRequestName, testRequestUID, time.Now().Add(time.Hour), testTransactionDetail())
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if err := kubeClient.Delete(ctx, completed); err != nil {
		t.Fatalf("delete the recorded transaction: %v", err)
	}
	recreated, err := store.create(ctx, namespace, testRequestName, testRequestUID, time.Now().Add(time.Hour), testTransactionDetail())
	if err != nil {
		t.Fatalf("recreate the transaction: %v", err)
	}

	if err := store.remove(ctx, completed); err != nil {
		t.Fatalf("expected removing a replaced transaction to be tolerated, got %v", err)
	}
	stored := &cmpv1alpha1.CMPTransaction{}
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: testRequestName}, stored); err != nil {
		t.Fatalf("expected the recreated transaction to survive, got %v", err)
	}
	if stored.UID != recreated.UID {
		t.Fatalf("expected the recreated transaction %q, got %q", recreated.UID, stored.UID)
	}
	if err := store.remove(ctx, recreated); err != nil {
		t.Fatalf("remove the recreated transaction: %v", err)
	}
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: testRequestName}, stored); !apierrors.IsNotFound(err) {
		t.Fatalf("expected the recreated transaction to be removed by its own reconcile, got %v", err)
	}
}

// TestTransactionStoreDiscardsForeignStateAgainstAPIServer verifies a reused name is not resumed.
func TestTransactionStoreDiscardsForeignStateAgainstAPIServer(t *testing.T) {
	kubeClient := startEnvtest(t)
	ctx := context.Background()
	namespace := "cmp-transaction-foreign"
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	store := &transactionStore{reader: kubeClient, writer: kubeClient}
	if _, err := store.create(ctx, namespace, testRequestName, testRequestUID, time.Now().Add(time.Hour), testTransactionDetail()); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	loaded, err := store.load(ctx, namespace, testRequestName, types.UID("99999999-9999-9999-9999-999999999999"))
	if err != nil {
		t.Fatalf("load with a foreign UID: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected the transaction of a different request to be discarded")
	}
	stored := &cmpv1alpha1.CMPTransaction{}
	err = kubeClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: testRequestName}, stored)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected the discarded transaction to be deleted, got %v", err)
	}
}
