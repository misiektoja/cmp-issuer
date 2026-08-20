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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// asyncOptions selects the deferred behavior of the asynchronous mock CMP server.
type asyncOptions struct {
	// CertReqID is the identifier the server echoes in every response of the transaction.
	CertReqID int64
	// PollsBeforeIssue is the number of pollReq messages answered with pollRep before the CP.
	PollsBeforeIssue int
	// CheckAfterSeconds is the wait the server requests in every pollRep.
	CheckAfterSeconds int64
	// PollRepCertReqID overrides the identifier returned in pollRep to simulate a mismatch.
	PollRepCertReqID *int64
	// OmitPollExtraCerts drops extraCerts from poll responses, as deployed servers do.
	OmitPollExtraCerts bool
}

// asyncState records the messages an asynchronous transaction exchanged.
type asyncState struct {
	mu             sync.Mutex
	bodies         []pkicmp.BodyType
	transactionIDs [][]byte
	recipNonces    [][]byte
	lastSenderName []byte
}

// record stores one observed request for later transaction linkage assertions.
func (s *asyncState) record(message *pkicmp.PKIMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies = append(s.bodies, message.Body.Type)
	s.transactionIDs = append(s.transactionIDs, append([]byte(nil), message.Header.TransactionID...))
	s.recipNonces = append(s.recipNonces, append([]byte(nil), message.Header.RecipNonce...))
}

// observed returns the request bodies in order.
func (s *asyncState) observed() []pkicmp.BodyType {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]pkicmp.BodyType(nil), s.bodies...)
}

// newAsyncCMPServer creates a server that answers waiting, then pollRep, then the issued certificate.
func newAsyncCMPServer(t *testing.T, pki testPKI, password []byte, options asyncOptions) (*httptest.Server, *asyncState) {
	t.Helper()
	state := &asyncState{}
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestDER, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		message, err := pkicmp.ParsePKIMessage(requestDER)
		if err != nil {
			t.Errorf("parse request: %v", err)
			return
		}
		verification, err := message.Verify(pkicmp.VerifyOptions{SharedSecret: password, SenderKID: message.Header.SenderKID})
		if err != nil {
			t.Errorf("verify request protection: %v", err)
			return
		}
		state.record(message)
		senderNonce := make([]byte, 16)
		if _, err := rand.Read(senderNonce); err != nil {
			t.Fatalf("generate sender nonce: %v", err)
		}
		response := &pkicmp.PKIMessage{Header: pkicmp.PKIHeader{PVNO: pkicmp.PVNO2, Sender: pkicmp.NewDirectoryName(pki.CACertificate.Subject), TransactionID: append([]byte(nil), message.Header.TransactionID...), RecipNonce: append([]byte(nil), message.Header.SenderNonce...), SenderNonce: senderNonce}}
		switch message.Body.Type {
		case pkicmp.BodyTypeP10CR:
			response.Body = pkicmp.NewCPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{CertReqID: options.CertReqID, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}}}})
		case pkicmp.BodyTypePollReq:
			content, parseErr := message.Body.PollReq()
			if parseErr != nil || len(*content) != 1 {
				t.Errorf("parse pollReq: %v", parseErr)
				return
			}
			if (*content)[0] != options.CertReqID {
				t.Errorf("expected pollReq certReqId %d, got %d", options.CertReqID, (*content)[0])
				return
			}
			polls++
			if polls <= options.PollsBeforeIssue {
				replyCertReqID := options.CertReqID
				if options.PollRepCertReqID != nil {
					replyCertReqID = *options.PollRepCertReqID
				}
				body := pkicmp.PollRepContent{{CertReqID: replyCertReqID, CheckAfter: options.CheckAfterSeconds}}
				response.Body = pkicmp.NewPollRepBody(&body)
				break
			}
			certificateRequest, parseErr := x509.ParseCertificateRequest(state.pendingCSR())
			if parseErr != nil {
				t.Errorf("parse stored CSR: %v", parseErr)
				return
			}
			leaf := issueLeaf(t, pki, certificateRequest, certificateRequest.PublicKey)
			response.Body = pkicmp.NewCPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{CertReqID: options.CertReqID, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}, CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: leaf.Raw}}}}}})
		case pkicmp.BodyTypeCertConf:
			response.Body = pkicmp.NewPKIConfBody()
		default:
			t.Errorf("unexpected request body %s", message.Body.Type)
			return
		}
		var credentials pkicmp.Credentials
		if verification.MACVerified {
			credentials, err = pkicmp.NewMACCredentials(password, verification.ProtectionParams)
		} else {
			credentials, err = pkicmp.NewSignatureCredentials(pki.CAKey, pki.CACertificate)
		}
		if err != nil {
			t.Errorf("create response credentials: %v", err)
			return
		}
		if err := credentials.Protect(response); err != nil {
			t.Errorf("protect response: %v", err)
			return
		}
		if options.OmitPollExtraCerts && message.Body.Type != pkicmp.BodyTypeP10CR {
			response.ExtraCerts = nil
		}
		responseDER, err := response.MarshalBinary()
		if err != nil {
			t.Errorf("marshal response: %v", err)
			return
		}
		writer.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = writer.Write(responseDER)
	}))
	return server, state
}

// setPendingCSR stores the CSR the deferred transaction will eventually issue.
func (s *asyncState) setPendingCSR(csr []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSenderName = append([]byte(nil), csr...)
}

// pendingCSR returns the stored CSR of the deferred transaction.
func (s *asyncState) pendingCSR() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSenderName
}

// TestAsynchronousTransactionPollsUntilIssued verifies waiting, pollReq and the final CP on the wire.
func TestAsynchronousTransactionPollsUntilIssued(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newAsyncCMPServer(t, pki, password, asyncOptions{CertReqID: ResponseCertReqIDLegacyZero, PollsBeforeIssue: 1, CheckAfterSeconds: 7})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	request.TransactionID = []byte("0123456789abcdef")
	state.setPendingCSR(request.CSRDER)

	client := NewClient()
	result, err := client.EnrollP10CR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if result.Pending == nil {
		t.Fatal("expected the waiting response to report a pending transaction")
	}
	if result.Pending.CertReqID != ResponseCertReqIDLegacyZero {
		t.Fatalf("expected the echoed certReqId, got %d", result.Pending.CertReqID)
	}
	if len(result.Pending.RecipNonce) == 0 {
		t.Fatal("expected the pending state to carry the next recipient nonce")
	}
	if result.Pending.CheckAfter != 0 {
		t.Fatalf("expected no server wait in the first waiting response, got %s", result.Pending.CheckAfter)
	}

	poll := PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner}
	result, err = client.PollP10CR(context.Background(), poll)
	if err != nil {
		t.Fatalf("PollP10CR returned error: %v", err)
	}
	if result.Pending == nil {
		t.Fatal("expected the pollRep to report a pending transaction")
	}
	if result.Pending.CheckAfter != 7*time.Second {
		t.Fatalf("expected the server requested wait of 7s, got %s", result.Pending.CheckAfter)
	}

	poll = PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner}
	result, err = client.PollP10CR(context.Background(), poll)
	if err != nil {
		t.Fatalf("final PollP10CR returned error: %v", err)
	}
	if result.Pending != nil {
		t.Fatal("expected the final poll to issue a certificate")
	}
	if len(result.Chain) == 0 {
		t.Fatal("expected an issued chain")
	}
	result, err = confirmToCompletion(t, client, request, result)
	if err != nil {
		t.Fatalf("confirmation returned error: %v", err)
	}
	if !result.ExplicitConfirmation {
		t.Fatal("expected the polled transaction to be confirmed explicitly")
	}

	expected := []pkicmp.BodyType{pkicmp.BodyTypeP10CR, pkicmp.BodyTypePollReq, pkicmp.BodyTypePollReq, pkicmp.BodyTypeCertConf}
	observed := state.observed()
	if len(observed) != len(expected) {
		t.Fatalf("expected %d messages, got %v", len(expected), observed)
	}
	for index, body := range expected {
		if observed[index] != body {
			t.Fatalf("expected message %d to be %s, got %s", index, body, observed[index])
		}
	}
	for index, transactionID := range state.transactionIDs {
		if !bytes.Equal(transactionID, request.TransactionID) {
			t.Fatalf("message %d used transaction ID %x instead of the pinned one", index, transactionID)
		}
	}
}

// TestAsynchronousTransactionRejectsMismatchedPollRep verifies a foreign certReqId ends the transaction.
func TestAsynchronousTransactionRejectsMismatchedPollRep(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	foreign := int64(41)
	server, state := newAsyncCMPServer(t, pki, password, asyncOptions{CertReqID: ResponseCertReqIDLegacyZero, PollsBeforeIssue: 1, PollRepCertReqID: &foreign})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	request.TransactionID = []byte("fedcba9876543210")
	state.setPendingCSR(request.CSRDER)

	client := NewClient()
	result, err := client.EnrollP10CR(context.Background(), request)
	if err != nil || result.Pending == nil {
		t.Fatalf("expected a pending transaction, got %v", err)
	}
	poll := PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner}
	_, err = client.PollP10CR(context.Background(), poll)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != "certReqIdMismatch" {
		t.Fatalf("expected a certReqId mismatch security failure, got %v", err)
	}
}

// TestAsynchronousTransactionReusesRetainedSigner verifies polling succeeds when a server omits extraCerts.
func TestAsynchronousTransactionReusesRetainedSigner(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newAsyncCMPServer(t, pki, password, asyncOptions{CertReqID: ResponseCertReqIDLegacyZero, PollsBeforeIssue: 0, OmitPollExtraCerts: true})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	request.TransactionID = []byte("0f1e2d3c4b5a6978")
	state.setPendingCSR(request.CSRDER)

	client := NewClient()
	result, err := client.EnrollP10CR(context.Background(), request)
	if err != nil || result.Pending == nil {
		t.Fatalf("expected a pending transaction, got %v", err)
	}
	poll := PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner}
	result, err = client.PollP10CR(context.Background(), poll)
	if err != nil {
		t.Fatalf("expected the retained signer to verify the poll response, got %v", err)
	}
	if len(result.Chain) == 0 {
		t.Fatal("expected an issued chain")
	}
}

// TestPollRequiresRecordedTransactionState verifies polling without linkage state is refused.
func TestPollRequiresRecordedTransactionState(t *testing.T) {
	pki := newTestPKI(t)
	request := baseEnrollmentRequest(t, pki, "https://example.test/cmp")
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: []byte("secret"), IterationCount: 1024}
	_, err := NewClient().PollP10CR(context.Background(), PollRequest{Enrollment: request, CertReqID: 0})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindPermanent {
		t.Fatalf("expected a permanent validation failure, got %v", err)
	}
}
