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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	// TransactionPhaseEnrolling marks a transaction whose enrollment request may be in flight.
	TransactionPhaseEnrolling = "Enrolling"
	// TransactionPhasePolling marks a transaction the server answered with waiting.
	TransactionPhasePolling = "Polling"
	// TransactionPhaseConfirming marks a transaction whose certificate is issued and validated but
	// not yet confirmed. The chain is already recorded, so confirmation resumes after a restart
	// instead of failing a request whose certificate exists.
	TransactionPhaseConfirming = "Confirming"
	// TransactionPhaseIssued marks a transaction whose validated chain is recorded and confirmed, so
	// that a restart before cert-manager stored the certificate returns it instead of enrolling again.
	TransactionPhaseIssued = "Issued"

	// TransactionOperationP10CR is the CMP operation of a PKCS #10 initial enrollment.
	TransactionOperationP10CR = "P10CR"

	// TransactionIssuerKindNamespaced identifies a namespaced CMPIssuer.
	TransactionIssuerKindNamespaced = "CMPIssuer"
	// TransactionIssuerKindCluster identifies a cluster scoped CMPClusterIssuer.
	TransactionIssuerKindCluster = "CMPClusterIssuer"
)

// TransactionIssuerReference identifies the issuer that served a transaction, including its UID so
// that a recreated issuer reusing the same name is distinguishable in the recorded history.
type TransactionIssuerReference struct {
	// Name is the issuer resource name.
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`
	// Kind is the issuer resource kind.
	// +kubebuilder:validation:Enum=CMPIssuer;CMPClusterIssuer
	// +required
	Kind string `json:"kind"`
	// UID distinguishes a recreated issuer that reuses a name.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	UID string `json:"uid,omitempty"`
}

// CMPTransactionSpec identifies the CertificateRequest that owns an in-flight CMP transaction.
// The controller writes this resource before it sends the enrollment request, so that a restart
// resumes the existing transaction by polling instead of enrolling a second time.
type CMPTransactionSpec struct {
	// CertificateRequestName is the CertificateRequest this transaction enrolls.
	// +kubebuilder:validation:MaxLength=253
	// +required
	CertificateRequestName string `json:"certificateRequestName"`
	// CertificateRequestUID distinguishes a recreated CertificateRequest that reuses a name.
	// +kubebuilder:validation:MaxLength=253
	// +required
	CertificateRequestUID string `json:"certificateRequestUID"`
	// TransactionID is the CMP transactionID that every message of this transaction carries.
	// +kubebuilder:validation:MaxLength=64
	// +required
	TransactionID []byte `json:"transactionID"`
	// Deadline is the instant after which the transaction is abandoned as failed.
	// +required
	Deadline metav1.Time `json:"deadline"`
	// CSRDigest is the lowercase hexadecimal SHA-256 digest of the DER CSR this transaction enrolls.
	// It identifies the enrolled request in diagnostics and guards a recorded chain from being
	// returned for a different CSR.
	// +kubebuilder:validation:MaxLength=64
	// +optional
	CSRDigest string `json:"csrDigest,omitempty"`
	// IssuerRef identifies the issuer that served this transaction.
	// +optional
	IssuerRef *TransactionIssuerReference `json:"issuerRef,omitempty"`
	// Operation is the CMP operation this transaction performs.
	// +kubebuilder:validation:Enum=P10CR
	// +optional
	Operation string `json:"operation,omitempty"`
	// ProtocolVersion is the CMP protocol version of every message in this transaction.
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=3
	// +optional
	ProtocolVersion int32 `json:"protocolVersion,omitempty"`
}

// CMPTransactionStatus records the progress of an in-flight CMP transaction.
type CMPTransactionStatus struct {
	// Phase reports whether the enrollment request is in flight, the server asked the client to poll,
	// the certificate awaits confirmation, or the validated chain is recorded and confirmed.
	// +kubebuilder:validation:Enum=Enrolling;Polling;Confirming;Issued
	// +optional
	Phase string `json:"phase,omitempty"`
	// IssuedChain is the validated leaf-first certificate chain in DER form, recorded before the
	// chain is returned so that a restart in that window does not enroll a second certificate.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	IssuedChain [][]byte `json:"issuedChain,omitempty"`
	// CompletionTime records when the transaction reached the Issued phase.
	// +optional
	CompletionTime metav1.Time `json:"completionTime,omitzero"`
	// RecipNonce is the sender nonce of the last accepted response, echoed by the next request.
	// +kubebuilder:validation:MaxLength=64
	// +optional
	RecipNonce []byte `json:"recipNonce,omitempty"`
	// RequestNonce is the sender nonce of the request whose response the server delayed. RFC 9483
	// section 4.4 requires the client to keep it for the whole transaction because a conformant
	// server echoes it in the recipient nonce of the final response instead of the nonce of the
	// last poll request.
	// +kubebuilder:validation:MaxLength=64
	// +optional
	RequestNonce []byte `json:"requestNonce,omitempty"`
	// CertReqID is the certificate request identifier that the server polls against.
	// +optional
	CertReqID *int64 `json:"certReqID,omitempty"`
	// ResponseSigner is the DER encoded certificate that protected the last response. It is retained
	// because servers such as NCM omit extraCerts and senderKID from later messages of a transaction.
	// +optional
	ResponseSigner []byte `json:"responseSigner,omitempty"`
	// Polls counts the pollReq messages already sent, which the maximumPolls limit bounds. The
	// enrollment request that first received a waiting response is not counted.
	// +optional
	Polls int32 `json:"polls,omitempty"`
	// LastTransitionTime records when the phase last changed.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitzero"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=".spec.issuerRef.name"
// +kubebuilder:printcolumn:name="Polls",type=integer,JSONPath=".status.polls"
// +kubebuilder:printcolumn:name="Deadline",type=date,JSONPath=".spec.deadline"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// CMPTransaction records the state of one CMP transaction so that an asynchronous enrollment
// survives a controller restart and an issued certificate is never enrolled twice. The controller
// creates it before the first message is sent, removes it when the transaction fails and retains it
// with the issued chain afterwards, until it is garbage collected with the CertificateRequest that
// owns it.
type CMPTransaction struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of CMPTransaction
	// +required
	Spec CMPTransactionSpec `json:"spec"`

	// status defines the observed state of CMPTransaction
	// +optional
	Status CMPTransactionStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CMPTransactionList contains a list of CMPTransaction
type CMPTransactionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CMPTransaction `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &CMPTransaction{}, &CMPTransactionList{})
		return nil
	})
}
