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
	// OperationP10CR identifies PKCS #10 enrollment and compatibility renewal.
	OperationP10CR = "P10CR"
	// OperationKUR identifies a certificate-authenticated Key Update Request.
	OperationKUR = "KUR"
	// ResponseCertReqIDStandard is the P10CR response identifier required by RFC 9810 and RFC 9483.
	ResponseCertReqIDStandard int64 = -1
	// ResponseCertReqIDLegacyZero is the identifier returned by servers that reuse the CRMF request index.
	ResponseCertReqIDLegacyZero int64 = 0
)

// Client enrolls or updates a certificate, resumes a waiting transaction and confirms issuance.
type Client interface {
	EnrollP10CR(context.Context, EnrollmentRequest) (EnrollmentResult, error)
	EnrollKUR(context.Context, EnrollmentRequest) (EnrollmentResult, error)
	PollP10CR(context.Context, PollRequest) (EnrollmentResult, error)
	ConfirmP10CR(context.Context, ConfirmRequest) (EnrollmentResult, error)
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

// EnrollmentRequest contains validated inputs for one P10CR or KUR exchange.
// A nil ResponseCertReqID accepts either the standard or the legacy zero response identifier.
// TransactionID pins the CMP transaction identifier so a caller can persist it before the request
// is sent and resume the same transaction later. It is generated when empty, so a caller that polls
// or confirms must supply it rather than let the transaction identifier be generated. Every
// enrollment that is not implicitly confirmed needs it, because confirmation is a separate call.
type EnrollmentRequest struct {
	Operation         string
	EndpointURL       string
	Timeout           time.Duration
	MaxResponseSize   int64
	Sender            *pkix.Name
	Recipient         pkix.Name
	ImplicitConfirm   bool
	RejectGrantedMods bool
	// AllowSignedMACResponse accepts a signature-protected answer to a MAC-protected request when the
	// signer chains to CMPTrust. It is ignored when the request is signature-protected already.
	AllowSignedMACResponse bool
	ResponseCertReqID      *int64
	TransactionID          []byte
	CSRDER                 []byte
	RequestedPrivateKey    crypto.Signer
	Protection             Protection
	CMPTrust               *x509.CertPool
	TLSRoots               *x509.CertPool
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
	// RequestNonce is the sender nonce of the request whose response the server delayed. RFC 9483
	// section 4.4 requires the client to keep it because a conformant server echoes it in the
	// recipNonce of the final response rather than the nonce of the last pollReq.
	RequestNonce []byte
}

// ConfirmRequest sends the certConf of an issued certificate, or resumes a confirmation the server
// delayed. RequestNonce is empty on the first call and set once certConf has been sent, which is how
// a resumed confirmation continues with pollReq rather than repeating certConf.
type ConfirmRequest struct {
	// Enrollment carries the unchanged issuer configuration, credentials and CSR of the transaction.
	Enrollment EnrollmentRequest
	// Certificate is the issued leaf whose hash certConf carries.
	Certificate *x509.Certificate
	// CertReqID identifies the confirmed request inside the transaction.
	CertReqID int64
	// RecipNonce is the sender nonce of the last accepted response.
	RecipNonce []byte
	// ResponseSigner is the signer already validated for this transaction, reused when a server omits
	// extraCerts and senderKID from later messages.
	ResponseSigner *x509.Certificate
	// RequestNonce is the sender nonce of the certConf whose response the server delayed. RFC 9483
	// section 4.4 requires the client to keep it because a conformant server echoes it in the
	// recipNonce of the final pkiConf rather than the nonce of the last pollReq.
	RequestNonce []byte
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
	// RequestNonce is the sender nonce of the request whose response the server delayed, which the
	// caller must persist and return in the next PollRequest.
	RequestNonce []byte
}

// EnrollmentResult contains a validated leaf-first certificate chain, or the state needed to poll.
type EnrollmentResult struct {
	Chain                 []*x509.Certificate
	ExtraCertificateCount int
	ExplicitConfirmation  bool
	ResponseCertReqID     int64
	// Pending is set when the server has not decided yet and the transaction must be polled.
	Pending *PendingTransaction
	// PendingConfirmation is set when the certificate is issued and validated but not yet confirmed.
	// Chain is populated alongside it, so the caller records the chain before confirming and a
	// confirmation interrupted by a restart resumes instead of discarding an issued certificate.
	PendingConfirmation *PendingTransaction
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
