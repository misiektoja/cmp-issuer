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
	"crypto/rand"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

const (
	// certificateRequestAPIVersion is the owner API version of every request this signer serves.
	certificateRequestAPIVersion = "cert-manager.io/v1"
	// certificateRequestKind is the owner kind of every request this signer serves.
	certificateRequestKind = "CertificateRequest"
	// transactionIDLength is the CMP transaction identifier size required by RFC 9810 section 5.1.1.
	transactionIDLength = 16
)

// transactionStore persists CMP transaction state so an asynchronous enrollment survives a restart.
// Reads bypass the informer cache because a stale miss would start a second enrollment for a
// transaction that is already in flight.
type transactionStore struct {
	reader client.Reader
	writer client.Client
}

// load returns the stored transaction of a CertificateRequest, or nil when none is recorded.
func (t *transactionStore) load(ctx context.Context, namespace string, name string, uid types.UID) (*cmpv1alpha1.CMPTransaction, error) {
	transaction := &cmpv1alpha1.CMPTransaction{}
	if err := t.reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, transaction); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read CMP transaction state: %w", err)
	}
	if transaction.Spec.CertificateRequestUID != string(uid) {
		// The name was reused by a recreated CertificateRequest, so the recorded transaction belongs
		// to a request that no longer exists and must not be resumed.
		if err := t.writer.Delete(ctx, transaction); err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("remove stale CMP transaction state: %w", err)
		}
		return nil, nil
	}
	return transaction, nil
}

// create records a transaction before its first message is sent so that a crash cannot hide it.
func (t *transactionStore) create(ctx context.Context, namespace string, name string, uid types.UID, deadline time.Time) (*cmpv1alpha1.CMPTransaction, error) {
	transactionID := make([]byte, transactionIDLength)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, fmt.Errorf("generate CMP transaction ID: %w", err)
	}
	transaction := &cmpv1alpha1.CMPTransaction{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: certificateRequestAPIVersion,
				Kind:       certificateRequestKind,
				Name:       name,
				UID:        uid,
			}},
		},
		Spec: cmpv1alpha1.CMPTransactionSpec{
			CertificateRequestName: name,
			CertificateRequestUID:  string(uid),
			TransactionID:          transactionID,
			Deadline:               metav1.NewTime(deadline),
		},
	}
	if err := t.writer.Create(ctx, transaction); err != nil {
		return nil, fmt.Errorf("record CMP transaction state: %w", err)
	}
	transaction.Status.Phase = cmpv1alpha1.TransactionPhaseEnrolling
	transaction.Status.LastTransitionTime = metav1.Now()
	if err := t.writer.Status().Update(ctx, transaction); err != nil {
		return nil, fmt.Errorf("record CMP transaction phase: %w", err)
	}
	return transaction, nil
}

// recordPending stores the state required to send the next poll of a transaction.
func (t *transactionStore) recordPending(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, pending *protocol.PendingTransaction) error {
	certReqID := pending.CertReqID
	transaction.Status.Phase = cmpv1alpha1.TransactionPhasePolling
	transaction.Status.RecipNonce = pending.RecipNonce
	transaction.Status.CertReqID = &certReqID
	transaction.Status.LastTransitionTime = metav1.Now()
	if pending.ResponseSigner != nil {
		transaction.Status.ResponseSigner = pending.ResponseSigner.Raw
	}
	if err := t.writer.Status().Update(ctx, transaction); err != nil {
		return fmt.Errorf("record CMP poll state: %w", err)
	}
	return nil
}

// remove deletes transaction state once the transaction reached a terminal outcome.
func (t *transactionStore) remove(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction) error {
	if err := t.writer.Delete(ctx, transaction); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("remove CMP transaction state: %w", err)
	}
	return nil
}
