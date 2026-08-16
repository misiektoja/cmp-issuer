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
	created, err := store.create(ctx, namespace, testRequestName, testRequestUID, deadline)
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
	pending := &protocol.PendingTransaction{CertReqID: protocol.ResponseCertReqIDStandard, RecipNonce: []byte{1, 2, 3, 4}, ResponseSigner: signer}
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

// TestTransactionStoreDiscardsForeignStateAgainstAPIServer verifies a reused name is not resumed.
func TestTransactionStoreDiscardsForeignStateAgainstAPIServer(t *testing.T) {
	kubeClient := startEnvtest(t)
	ctx := context.Background()
	namespace := "cmp-transaction-foreign"
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	store := &transactionStore{reader: kubeClient, writer: kubeClient}
	if _, err := store.create(ctx, namespace, testRequestName, testRequestUID, time.Now().Add(time.Hour)); err != nil {
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
