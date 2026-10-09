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

package protocol

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// anchorEnrollmentRequest configures signature protection and an out-of-band response trust anchor.
func anchorEnrollmentRequest(t *testing.T, pki testPKI, endpoint string) EnrollmentRequest {
	t.Helper()
	request := baseEnrollmentRequest(t, pki, endpoint)
	request.CMPTrustCertificates = []*x509.Certificate{pki.CACertificate}
	request.Protection.Signature = &SignatureProtection{PrivateKey: pki.BootstrapKey, Certificate: pki.BootstrapCertificate, Chain: []*x509.Certificate{pki.CACertificate}}
	return request
}

// TestAnchorSignerP10CR verifies initial and confirmation responses can omit a configured signer.
func TestAnchorSignerP10CR(t *testing.T) {
	for _, test := range []struct {
		name          string
		mismatchedKID bool
		password      []byte
		strict        bool
	}{
		{name: "signature"},
		{name: "RFC9483", strict: true},
		{name: "mismatched senderKID", mismatchedKID: true},
		{name: "signed MAC response", password: []byte("test-shared-secret")},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			request := anchorEnrollmentRequest(t, pki, "")
			server, state := newMockCMPServer(t, pki, test.password, request.CMPTrust, mockOptions{CertReqID: ResponseCertReqIDStandard, OmitExtraCerts: true, MismatchedSenderKID: test.mismatchedKID, ForceSignature: true})
			defer server.Close()
			request.EndpointURL = server.URL
			if test.strict {
				request.ResponseCertReqID = pinCertReqID(ResponseCertReqIDStandard)
				request.RequireKUPCAPubsAbsent = true
			}
			if test.password != nil {
				request.Protection = Protection{Password: &PasswordProtection{Reference: []byte("test-reference"), Secret: test.password, IterationCount: 1024}}
				request.AllowSignedMACResponse = true
			}
			result, err := NewClient().EnrollP10CR(context.Background(), request)
			if err != nil {
				t.Fatalf("enroll with an omitted anchor: %v", err)
			}
			requireAnchorSigner(t, result.PendingConfirmation, pki.CACertificate)
			result, err = confirmToCompletion(t, NewClient(), request, result)
			if err != nil || !result.ExplicitConfirmation || state.count() != 2 {
				t.Fatalf("confirm with an omitted anchor: result=%+v messages=%d error=%v", result, state.count(), err)
			}
		})
	}
}

// TestAnchorSignerKUR verifies both key rotation policies accept an omitted anchor signer.
func TestAnchorSignerKUR(t *testing.T) {
	for _, test := range keyRotationCases {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			request := kurEnrollmentRequest(t, pki, "", test.rotateKey)
			request.CMPTrustCertificates = []*x509.Certificate{pki.CACertificate}
			server, _ := newMockCMPServer(t, pki, nil, request.CMPTrust, mockOptions{CertReqID: ResponseCertReqIDLegacyZero, OmitExtraCerts: true})
			defer server.Close()
			request.EndpointURL = server.URL
			result, err := NewClient().EnrollKUR(context.Background(), request)
			if err != nil {
				t.Fatalf("KUR with an omitted anchor: %v", err)
			}
			requireAnchorSigner(t, result.PendingConfirmation, pki.CACertificate)
			result, err = confirmToCompletion(t, NewClient(), request, result)
			if err != nil || !result.ExplicitConfirmation || !PublicKeysEqual(result.Chain[0].PublicKey, request.RequestedPrivateKey.Public()) {
				t.Fatalf("confirm KUR with an omitted anchor: %v", err)
			}
		})
	}
}

// TestAnchorSignerRejectsInvalidResponses preserves authentication and transaction checks without extraCerts.
func TestAnchorSignerRejectsInvalidResponses(t *testing.T) {
	for _, test := range []struct {
		name           string
		options        mockOptions
		wrongRecipient bool
		untrusted      bool
		failure        string
	}{
		{name: "wrong authority", wrongRecipient: true, failure: testWrongAuthority},
		{name: "non-anchor signer", options: mockOptions{ImpostorAuthority: true}, failure: testBadMessageCheck},
		{name: "tampered protection", options: mockOptions{InvalidProtection: true}, failure: testBadMessageCheck},
		{name: "tampered confirmation", options: mockOptions{InvalidPKIConf: true}, failure: testBadMessageCheck},
		{name: "absent sender", options: mockOptions{NullSender: true}, failure: testWrongAuthority},
		{name: "sender subject mismatch", options: mockOptions{WrongSignerSubject: true}, failure: testBadMessageCheck},
		{name: "untrusted candidate", untrusted: true, failure: testBadMessageCheck},
		{name: "transaction ID", options: mockOptions{WrongTransactionID: true}, failure: "transactionIdMismatch"},
		{name: "recipient nonce", options: mockOptions{WrongNonce: true}, failure: "nonceMismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			request := anchorEnrollmentRequest(t, pki, "")
			test.options.CertReqID = ResponseCertReqIDStandard
			test.options.OmitExtraCerts = true
			server, _ := newMockCMPServer(t, pki, nil, request.CMPTrust, test.options)
			defer server.Close()
			request.EndpointURL = server.URL
			if test.wrongRecipient {
				request.Recipient = pkix.Name{CommonName: "Another CA"}
			}
			if test.untrusted {
				request.CMPTrust = x509.NewCertPool()
			}
			_, err := enrollAndConfirm(t, request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != test.failure {
				t.Fatalf("expected %s, got %v", test.failure, err)
			}
		})
	}
}

// requireAnchorSigner checks that a pending transaction retains the exact configured anchor.
func requireAnchorSigner(t *testing.T, pending *PendingTransaction, anchor *x509.Certificate) {
	t.Helper()
	if pending == nil || pending.ResponseSigner == nil || !pending.ResponseSigner.Equal(anchor) {
		t.Fatal("expected the configured anchor as the retained response signer")
	}
}

// TestAnchorSignerDelayedEnrollment verifies anchor discovery during waiting and pollRep responses.
func TestAnchorSignerDelayedEnrollment(t *testing.T) {
	pki := newTestPKI(t)
	server, state := newAsyncCMPServer(t, pki, nil, asyncOptions{CertReqID: ResponseCertReqIDStandard, PollsBeforeIssue: 1, OmitExtraCerts: true})
	defer server.Close()
	request := anchorEnrollmentRequest(t, pki, server.URL)
	state.setPendingCSR(request.CSRDER)
	result, err := NewClient().EnrollP10CR(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		requireAnchorSigner(t, result.Pending, pki.CACertificate)
		result, err = NewClient().PollP10CR(context.Background(), PollRequest{Enrollment: request, CertReqID: result.Pending.CertReqID, RecipNonce: result.Pending.RecipNonce, RequestNonce: result.Pending.RequestNonce})
		if err != nil {
			t.Fatalf("poll with an omitted anchor: %v", err)
		}
	}
	requireAnchorSigner(t, result.PendingConfirmation, pki.CACertificate)
	if _, err := confirmToCompletion(t, NewClient(), request, result); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(state.observed(), []pkicmp.BodyType{pkicmp.BodyTypeP10CR, pkicmp.BodyTypePollReq, pkicmp.BodyTypePollReq, pkicmp.BodyTypeCertConf}) {
		t.Fatalf("unexpected delayed enrollment exchange: %v", state.observed())
	}
}

// TestAnchorSignerDelayedConfirmation verifies a restored signer authenticates pollRep and pkiConf.
func TestAnchorSignerDelayedConfirmation(t *testing.T) {
	pki := newTestPKI(t)
	server, state := newDelayedConfirmationServer(t, pki, nil, confirmationOptions{Delays: 2, UsePollRep: true, PollRepCertReqID: ResponseCertReqIDStandard, EchoDelayedRequestNonce: true, OmitExtraCerts: true})
	defer server.Close()
	request := anchorEnrollmentRequest(t, pki, server.URL)
	result, err := NewClient().EnrollP10CR(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	requireAnchorSigner(t, result.PendingConfirmation, pki.CACertificate)
	// Only the persisted signer is available after restoring this transaction.
	request.CMPTrustCertificates = nil
	pending := result.PendingConfirmation
	for range 3 {
		requireAnchorSigner(t, pending, pki.CACertificate)
		restored, parseErr := x509.ParseCertificate(pending.ResponseSigner.Raw)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		confirmed, confirmErr := NewClient().ConfirmP10CR(context.Background(), ConfirmRequest{Enrollment: request, Certificate: result.Chain[0], CertReqID: pending.CertReqID, RecipNonce: pending.RecipNonce, ResponseSigner: restored, RequestNonce: pending.RequestNonce})
		if confirmErr != nil {
			t.Fatalf("confirm with a restored anchor signer: %v", confirmErr)
		}
		pending = confirmed.PendingConfirmation
	}
	if pending != nil || !slices.Equal(state.observed(), []pkicmp.BodyType{pkicmp.BodyTypeP10CR, pkicmp.BodyTypeCertConf, pkicmp.BodyTypePollReq, pkicmp.BodyTypePollReq}) {
		t.Fatalf("unexpected delayed confirmation exchange: %v", state.observed())
	}
}
