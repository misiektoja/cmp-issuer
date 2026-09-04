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
	"crypto/rand"
	"crypto/x509"
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

// transactionDetail describes the request a transaction enrolls, recorded when the transaction is
// created so that an in-flight or completed transaction is diagnosable on its own.
type transactionDetail struct {
	CSRDigest           string
	IssuerRef           cmpv1alpha1.TransactionIssuerReference
	ConfigurationDigest string
	Operation           string
	ProtocolVersion     int32
}

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
		// to a request that no longer exists and must not be resumed. A replacement written between the
		// read and the delete survives and is reported as a conflict that the next reconcile reads again.
		if err := t.writer.Delete(ctx, transaction, deletePreconditions(transaction)...); err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("remove stale CMP transaction state: %w", err)
		}
		return nil, nil
	}
	return transaction, nil
}

// create records a transaction before its first message is sent so that a crash cannot hide it.
func (t *transactionStore) create(ctx context.Context, namespace string, name string, uid types.UID, deadline time.Time, detail transactionDetail) (*cmpv1alpha1.CMPTransaction, error) {
	transactionID := make([]byte, transactionIDLength)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, fmt.Errorf("generate CMP transaction ID: %w", err)
	}
	issuerRef := detail.IssuerRef
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
			CSRDigest:              detail.CSRDigest,
			IssuerRef:              &issuerRef,
			ConfigurationDigest:    detail.ConfigurationDigest,
			Operation:              detail.Operation,
			ProtocolVersion:        detail.ProtocolVersion,
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

// recordConfirming stores the validated chain before certConf is sent, together with the state that
// resumes a confirmation the server delays. An interruption after this point continues the
// confirmation instead of discarding a certificate the server already issued.
func (t *transactionStore) recordConfirming(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, chain []*x509.Certificate, pending *protocol.PendingTransaction) error {
	certReqID := pending.CertReqID
	transaction.Status.Phase = cmpv1alpha1.TransactionPhaseConfirming
	transaction.Status.IssuedChain = encodeChain(chain)
	transaction.Status.RecipNonce = pending.RecipNonce
	// The nonce is assigned unconditionally because its meaning changes here. During enrollment it is
	// the delayed enrollment request nonce, while in the Confirming phase a non-empty value means
	// certConf has already been sent and its answer is polled for. Entering this phase with an empty
	// value must clear a recorded enrollment nonce because a resumed confirmation would otherwise
	// poll for a certConf that was never sent.
	transaction.Status.RequestNonce = pending.RequestNonce
	transaction.Status.CertReqID = &certReqID
	transaction.Status.LastTransitionTime = metav1.Now()
	if pending.ResponseSigner != nil {
		transaction.Status.ResponseSigner = pending.ResponseSigner.Raw
	}
	if err := t.writer.Status().Update(ctx, transaction); err != nil {
		return fmt.Errorf("record CMP confirmation state: %w", err)
	}
	return nil
}

// recordIssued marks a confirmed transaction complete, so that a restart before cert-manager stored
// the certificate returns the recorded chain instead of enrolling a second time.
func (t *transactionStore) recordIssued(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, chain []*x509.Certificate) error {
	now := metav1.Now()
	transaction.Status.Phase = cmpv1alpha1.TransactionPhaseIssued
	transaction.Status.IssuedChain = encodeChain(chain)
	transaction.Status.CompletionTime = now
	transaction.Status.LastTransitionTime = now
	if err := t.writer.Status().Update(ctx, transaction); err != nil {
		return fmt.Errorf("record issued CMP certificate chain: %w", err)
	}
	return nil
}

// encodeChain renders a leaf-first chain as the DER elements stored in a transaction record.
func encodeChain(chain []*x509.Certificate) [][]byte {
	encoded := make([][]byte, 0, len(chain))
	for _, certificate := range chain {
		encoded = append(encoded, append([]byte(nil), certificate.Raw...))
	}
	return encoded
}

// recordPending stores the state required to send the next poll of a transaction.
func (t *transactionStore) recordPending(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, pending *protocol.PendingTransaction) error {
	certReqID := pending.CertReqID
	transaction.Status.Phase = cmpv1alpha1.TransactionPhasePolling
	transaction.Status.RecipNonce = pending.RecipNonce
	if len(pending.RequestNonce) > 0 {
		transaction.Status.RequestNonce = pending.RequestNonce
	}
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

// remove deletes transaction state once the transaction reached a terminal outcome. A record already
// replaced under the same name answers with a conflict and is left to the reconcile that created it.
func (t *transactionStore) remove(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction) error {
	err := t.writer.Delete(ctx, transaction, deletePreconditions(transaction)...)
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return fmt.Errorf("remove CMP transaction state: %w", err)
	}
	return nil
}

// deletePreconditions binds a delete to the exact record that was read, so that a record deleted and
// recreated under the same name by another writer is never removed on behalf of a different request.
func deletePreconditions(transaction *cmpv1alpha1.CMPTransaction) []client.DeleteOption {
	if transaction.UID == "" {
		return nil
	}
	return []client.DeleteOption{client.Preconditions{UID: &transaction.UID}}
}
