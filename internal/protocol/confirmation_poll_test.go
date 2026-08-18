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
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// freshNonce returns a server sender nonce of the length RFC 9483 section 3.5 requires.
func freshNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	return nonce
}

// confirmationOptions configures how a test server delays the confirmation response.
type confirmationOptions struct {
	// Delays is how many times the confirmation leg is answered with a waiting status.
	Delays int
	// UsePollRep answers polls with pollRep instead of an error carrying status waiting.
	UsePollRep bool
	// PollRepCertReqID overrides the identifier echoed in pollRep bodies.
	PollRepCertReqID int64
	// EchoDelayedRequestNonce makes the final pkiConf echo the certConf nonce rather than the
	// nonce of the last pollReq, which RFC 9483 section 4.4 requires the client to accept.
	EchoDelayedRequestNonce bool
	// ForeignFinalNonce makes the final pkiConf echo an unrelated nonce.
	ForeignFinalNonce bool
}

// confirmationState records the confirmation exchange observed by the test server.
type confirmationState struct {
	mutex            sync.Mutex
	bodies           []pkicmp.BodyType
	pollCertReqIDs   []int64
	confirmationNnce []byte
	delaysRemaining  int
}

// observed returns the ordered body types the server received.
func (s *confirmationState) observed() []pkicmp.BodyType {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]pkicmp.BodyType(nil), s.bodies...)
}

// polls returns the certReqId of every pollReq the server received.
func (s *confirmationState) polls() []int64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]int64(nil), s.pollCertReqIDs...)
}

// newDelayedConfirmationServer serves a P10CR that is issued immediately but confirmed only after polling.
func newDelayedConfirmationServer(t *testing.T, pki testPKI, password []byte, options confirmationOptions) (*httptest.Server, *confirmationState) {
	t.Helper()
	state := &confirmationState{delaysRemaining: options.Delays}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		requestDER, err := io.ReadAll(httpRequest.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		message, err := pkicmp.ParsePKIMessage(requestDER)
		if err != nil {
			t.Errorf("parse request: %v", err)
			return
		}
		if _, err := message.Verify(pkicmp.VerifyOptions{SharedSecret: password, SenderKID: message.Header.SenderKID}); err != nil {
			t.Errorf("verify request protection: %v", err)
			return
		}
		state.mutex.Lock()
		state.bodies = append(state.bodies, message.Body.Type)
		response := &pkicmp.PKIMessage{Header: pkicmp.PKIHeader{PVNO: pkicmp.PVNO2, Sender: pkicmp.NewDirectoryName(pki.CACertificate.Subject), TransactionID: append([]byte(nil), message.Header.TransactionID...), SenderNonce: freshNonce(t), RecipNonce: append([]byte(nil), message.Header.SenderNonce...)}}
		switch message.Body.Type {
		case pkicmp.BodyTypeP10CR:
			certificateRequest, parseErr := message.Body.P10CR()
			if parseErr != nil {
				state.mutex.Unlock()
				t.Errorf("parse P10CR: %v", parseErr)
				return
			}
			leaf := issueLeaf(t, pki, certificateRequest, certificateRequest.PublicKey)
			response.Body = pkicmp.NewCPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{CertReqID: ResponseCertReqIDStandard, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}, CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: leaf.Raw}}}}}})
		case pkicmp.BodyTypeCertConf:
			state.confirmationNnce = append([]byte(nil), message.Header.SenderNonce...)
			if state.delaysRemaining > 0 {
				state.delaysRemaining--
				response.Body = pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}})
			} else {
				response.Body = pkicmp.NewPKIConfBody()
			}
		case pkicmp.BodyTypePollReq:
			poll, parseErr := message.Body.PollReq()
			if parseErr != nil || len(*poll) != 1 {
				state.mutex.Unlock()
				t.Errorf("parse pollReq: %v", parseErr)
				return
			}
			state.pollCertReqIDs = append(state.pollCertReqIDs, (*poll)[0])
			switch {
			case state.delaysRemaining > 0:
				state.delaysRemaining--
				if options.UsePollRep {
					response.Body = pkicmp.NewPollRepBody(&pkicmp.PollRepContent{{CertReqID: options.PollRepCertReqID, CheckAfter: 0}})
				} else {
					response.Body = pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}})
				}
			default:
				response.Body = pkicmp.NewPKIConfBody()
				if options.EchoDelayedRequestNonce {
					response.Header.RecipNonce = append([]byte(nil), state.confirmationNnce...)
				}
				if options.ForeignFinalNonce {
					response.Header.RecipNonce = []byte("an-unrelated-recipient-nonce")
				}
			}
		default:
			state.mutex.Unlock()
			t.Errorf("unexpected request body %s", message.Body.Type)
			return
		}
		state.mutex.Unlock()
		credentials, err := pkicmp.NewMACCredentials(password, pkicmp.WithPBM(), pkicmp.WithMACIterationCount(1024))
		if err != nil {
			t.Errorf("create response credentials: %v", err)
			return
		}
		if err := credentials.Protect(response); err != nil {
			t.Errorf("protect response: %v", err)
			return
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

// delayedConfirmationRequest builds a MAC protected enrollment for the delayed confirmation server.
func delayedConfirmationRequest(t *testing.T, pki testPKI, endpoint string, password []byte) EnrollmentRequest {
	t.Helper()
	request := baseEnrollmentRequest(t, pki, endpoint)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	return request
}

// TestConfirmationPollsUntilPKIConf verifies a delayed pkiConf is polled for rather than treated as a failure.
func TestConfirmationPollsUntilPKIConf(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newDelayedConfirmationServer(t, pki, password, confirmationOptions{Delays: 2, UsePollRep: true, PollRepCertReqID: ResponseCertReqIDStandard})
	defer server.Close()
	result, err := enrollAndConfirm(t, delayedConfirmationRequest(t, pki, server.URL, password))
	if err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if len(result.Chain) != 1 || !result.ExplicitConfirmation {
		t.Fatalf("expected one confirmed leaf, got %d certificates and confirmation %t", len(result.Chain), result.ExplicitConfirmation)
	}
	expected := []pkicmp.BodyType{pkicmp.BodyTypeP10CR, pkicmp.BodyTypeCertConf, pkicmp.BodyTypePollReq, pkicmp.BodyTypePollReq}
	observed := state.observed()
	if len(observed) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, observed)
	}
	for index, bodyType := range expected {
		if observed[index] != bodyType {
			t.Fatalf("expected %v, got %v", expected, observed)
		}
	}
	for _, certReqID := range state.polls() {
		if certReqID != ResponseCertReqIDStandard {
			t.Fatalf("RFC 9483 section 4.4 requires certReqId -1 when polling for a delayed message, got %d", certReqID)
		}
	}
}

// TestConfirmationPollAcceptsDelayedRequestNonce verifies the final response may echo the certConf nonce.
func TestConfirmationPollAcceptsDelayedRequestNonce(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, _ := newDelayedConfirmationServer(t, pki, password, confirmationOptions{Delays: 1, EchoDelayedRequestNonce: true})
	defer server.Close()
	if _, err := enrollAndConfirm(t, delayedConfirmationRequest(t, pki, server.URL, password)); err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
}

// TestConfirmationPollRejectsForeignNonce verifies an unrelated recipient nonce still fails the transaction.
func TestConfirmationPollRejectsForeignNonce(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, _ := newDelayedConfirmationServer(t, pki, password, confirmationOptions{Delays: 1, ForeignFinalNonce: true})
	defer server.Close()
	_, err := enrollAndConfirm(t, delayedConfirmationRequest(t, pki, server.URL, password))
	var protocolError *Error
	if !errors.As(err, &protocolError) || protocolError.Kind != ErrorKindSecurity {
		t.Fatalf("expected a security failure, got %v", err)
	}
}

// newDelayedEnrollmentServer answers P10CR with waiting and echoes the original request nonce in the
// final polled response, which is the behaviour RFC 9483 section 4.4 requires clients to accept.
func newDelayedEnrollmentServer(t *testing.T, pki testPKI, password []byte) *httptest.Server {
	t.Helper()
	var mutex sync.Mutex
	var enrollmentNonce []byte
	var pending *x509.CertificateRequest
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		requestDER, err := io.ReadAll(httpRequest.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		message, err := pkicmp.ParsePKIMessage(requestDER)
		if err != nil {
			t.Errorf("parse request: %v", err)
			return
		}
		if _, err := message.Verify(pkicmp.VerifyOptions{SharedSecret: password, SenderKID: message.Header.SenderKID}); err != nil {
			t.Errorf("verify request protection: %v", err)
			return
		}
		mutex.Lock()
		response := &pkicmp.PKIMessage{Header: pkicmp.PKIHeader{PVNO: pkicmp.PVNO2, Sender: pkicmp.NewDirectoryName(pki.CACertificate.Subject), TransactionID: append([]byte(nil), message.Header.TransactionID...), SenderNonce: freshNonce(t), RecipNonce: append([]byte(nil), message.Header.SenderNonce...)}}
		switch message.Body.Type {
		case pkicmp.BodyTypeP10CR:
			enrollmentNonce = append([]byte(nil), message.Header.SenderNonce...)
			certificateRequest, parseErr := message.Body.P10CR()
			if parseErr != nil {
				mutex.Unlock()
				t.Errorf("parse P10CR: %v", parseErr)
				return
			}
			pending = certificateRequest
			response.Body = pkicmp.NewCPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{CertReqID: ResponseCertReqIDStandard, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusWaiting}}}})
		case pkicmp.BodyTypePollReq:
			if pending == nil {
				mutex.Unlock()
				t.Error("received a poll before any enrollment")
				return
			}
			leaf := issueLeaf(t, pki, pending, pending.PublicKey)
			response.Body = pkicmp.NewCPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{CertReqID: ResponseCertReqIDStandard, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}, CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: leaf.Raw}}}}}})
			response.Header.RecipNonce = append([]byte(nil), enrollmentNonce...)
		case pkicmp.BodyTypeCertConf:
			response.Body = pkicmp.NewPKIConfBody()
		default:
			mutex.Unlock()
			t.Errorf("unexpected request body %s", message.Body.Type)
			return
		}
		mutex.Unlock()
		credentials, err := pkicmp.NewMACCredentials(password, pkicmp.WithPBM(), pkicmp.WithMACIterationCount(1024))
		if err != nil {
			t.Errorf("create response credentials: %v", err)
			return
		}
		if err := credentials.Protect(response); err != nil {
			t.Errorf("protect response: %v", err)
			return
		}
		responseDER, err := response.MarshalBinary()
		if err != nil {
			t.Errorf("marshal response: %v", err)
			return
		}
		writer.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = writer.Write(responseDER)
	}))
}

// TestPollAcceptsDelayedRequestNonce verifies the final polled response may echo the enrollment nonce.
func TestPollAcceptsDelayedRequestNonce(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server := newDelayedEnrollmentServer(t, pki, password)
	defer server.Close()
	request := delayedConfirmationRequest(t, pki, server.URL, password)
	request.TransactionID = []byte("delayed-nonce-transaction")
	client := NewClient()
	result, err := client.EnrollP10CR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if result.Pending == nil {
		t.Fatal("expected the server to answer with waiting")
	}
	if len(result.Pending.RequestNonce) == 0 {
		t.Fatal("expected the enrollment sender nonce to be reported for later polls")
	}
	polled, err := client.PollP10CR(context.Background(), PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner, RequestNonce: result.Pending.RequestNonce})
	if err != nil {
		t.Fatalf("PollP10CR returned error: %v", err)
	}
	if len(polled.Chain) != 1 {
		t.Fatalf("expected one issued certificate, got %d", len(polled.Chain))
	}
}

// TestConfirmationPollRejectsMismatchedPollRep verifies a pollRep for another request is rejected.
func TestConfirmationPollRejectsMismatchedPollRep(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, _ := newDelayedConfirmationServer(t, pki, password, confirmationOptions{Delays: 2, UsePollRep: true, PollRepCertReqID: ResponseCertReqIDLegacyZero})
	defer server.Close()
	_, err := enrollAndConfirm(t, delayedConfirmationRequest(t, pki, server.URL, password))
	var protocolError *Error
	if !errors.As(err, &protocolError) || protocolError.Kind != ErrorKindSecurity {
		t.Fatalf("expected a security failure, got %v", err)
	}
}
