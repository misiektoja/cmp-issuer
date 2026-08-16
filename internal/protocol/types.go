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

// Package protocol contains project-owned CMP transaction interfaces and adapters.
package protocol

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

const (
	// ResponseCertReqIDStandard is the P10CR response identifier required by RFC 9810 and RFC 9483.
	ResponseCertReqIDStandard int64 = -1
	// ResponseCertReqIDLegacyZero is the identifier returned by servers that reuse the CRMF request index.
	ResponseCertReqIDLegacyZero int64 = 0
)

// Client enrolls a signed PKCS #10 request through one protected CMP transaction and resumes a
// transaction that the server answered with waiting.
type Client interface {
	EnrollP10CR(context.Context, EnrollmentRequest) (EnrollmentResult, error)
	PollP10CR(context.Context, PollRequest) (EnrollmentResult, error)
}

// TransactionCodec executes CMP message state transitions independently of controller contracts.
type TransactionCodec interface {
	ExchangeP10CR(context.Context, EnrollmentRequest) (EnrollmentResult, error)
}

// PasswordProtection contains PasswordBasedMac credentials and fixed algorithm parameters.
type PasswordProtection struct {
	Reference      []byte
	Secret         []byte
	IterationCount int
}

// SignatureProtection contains bootstrap signing material separate from the requested key.
type SignatureProtection struct {
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}

// Protection contains exactly one configured CMP protection mode.
type Protection struct {
	Password  *PasswordProtection
	Signature *SignatureProtection
}

// EnrollmentRequest contains validated inputs for one P10CR exchange.
// A nil ResponseCertReqID accepts either the standard or the legacy zero response identifier.
// TransactionID pins the CMP transaction identifier so a caller can persist it before the request
// is sent and resume the same transaction later. It is generated when empty, so a caller that may
// need to poll must supply it rather than let the transaction identifier be generated.
type EnrollmentRequest struct {
	EndpointURL       string
	Timeout           time.Duration
	MaxResponseSize   int64
	Sender            *pkix.Name
	Recipient         pkix.Name
	ImplicitConfirm   bool
	RejectGrantedMods bool
	ResponseCertReqID *int64
	TransactionID     []byte
	CSRDER            []byte
	Protection        Protection
	CMPTrust          *x509.CertPool
	TLSRoots          *x509.CertPool
}

// PollRequest resumes a transaction whose enrollment response was waiting.
type PollRequest struct {
	// Enrollment carries the unchanged issuer configuration, credentials and CSR of the transaction.
	Enrollment EnrollmentRequest
	// RecipNonce is the sender nonce of the last accepted response.
	RecipNonce []byte
	// CertReqID identifies the pending request inside the transaction.
	CertReqID int64
	// ResponseSigner is the signer already validated for this transaction, reused when a server omits
	// extraCerts and senderKID from later messages.
	ResponseSigner *x509.Certificate
}

// PendingTransaction describes a server-side waiting response that the caller must poll for.
type PendingTransaction struct {
	// CertReqID identifies the pending request inside the transaction.
	CertReqID int64
	// RecipNonce is the sender nonce that the next request of this transaction must echo.
	RecipNonce []byte
	// ResponseSigner is the validated signer of the response, retained for later messages.
	ResponseSigner *x509.Certificate
	// CheckAfter is the server-requested wait before the next poll. It is zero when the server did
	// not state one, which happens on the first waiting response because only pollRep carries it.
	CheckAfter time.Duration
}

// EnrollmentResult contains a validated leaf-first certificate chain, or the state needed to poll.
type EnrollmentResult struct {
	Chain                 []*x509.Certificate
	ExtraCertificateCount int
	ExplicitConfirmation  bool
	ResponseCertReqID     int64
	// Pending is set when the server has not decided yet and the transaction must be polled.
	Pending *PendingTransaction
}

// ErrorKind classifies failures without matching text.
type ErrorKind string

const (
	// ErrorKindPermanent identifies invalid requests or unsupported protocol behavior.
	ErrorKindPermanent ErrorKind = "Permanent"
	// ErrorKindRetryable identifies transport or server failures safe to retry.
	ErrorKindRetryable ErrorKind = "Retryable"
	// ErrorKindPending identifies a server-side waiting response.
	ErrorKindPending ErrorKind = "Pending"
	// ErrorKindSecurity identifies failed authenticated transaction invariants.
	ErrorKindSecurity ErrorKind = "Security"
)

// Error is a typed sanitized CMP failure.
type Error struct {
	Kind         ErrorKind
	Operation    string
	Failure      string
	RequeueAfter time.Duration
	Err          error
}

// Error returns a sanitized description without credential material.
func (e *Error) Error() string {
	if e.Err == nil {
		return "CMP " + e.Operation + " failed"
	}
	return "CMP " + e.Operation + " failed: " + e.Err.Error()
}

// Unwrap exposes the structured underlying error.
func (e *Error) Unwrap() error { return e.Err }
