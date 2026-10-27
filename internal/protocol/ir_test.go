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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// testIRPassword is the shared secret of the MAC-protected IR tests.
var testIRPassword = []byte("test-shared-secret")

// irEnrollmentRequest returns an IR for a fresh workload key under the selected protection.
func irEnrollmentRequest(t *testing.T, pki testPKI, endpoint string, signature bool) EnrollmentRequest {
	t.Helper()
	request := baseEnrollmentRequest(t, pki, endpoint)
	csrDER, key := createCSR(t, "cmp-issuer-ir-test")
	request.Operation = OperationIR
	request.CSRDER = csrDER
	request.RequestedPrivateKey = key
	if signature {
		request.Protection.Signature = &SignatureProtection{PrivateKey: pki.BootstrapKey, Certificate: pki.BootstrapCertificate, Chain: []*x509.Certificate{pki.CACertificate}}
	} else {
		request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: testIRPassword, IterationCount: 1024}
	}
	return request
}

// irProtectionCases names the MAC and signature protection every IR test covers.
var irProtectionCases = []struct {
	name      string
	signature bool
}{
	{name: "PasswordBasedMac"},
	{name: "bootstrap certificate", signature: true},
}

// TestEnrollIR verifies an IR with CRMF proof of possession is answered by an IP and confirmed with certReqId 0.
func TestEnrollIR(t *testing.T) {
	for _, test := range irProtectionCases {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			bootstrapRoots := x509.NewCertPool()
			bootstrapRoots.AddCert(pki.CACertificate)
			server, state := newMockCMPServer(t, pki, testIRPassword, bootstrapRoots, mockOptions{})
			defer server.Close()
			request := irEnrollmentRequest(t, pki, server.URL, test.signature)
			client := NewClient()
			result, err := client.EnrollIR(context.Background(), request)
			if err == nil {
				result, err = confirmToCompletion(t, client, request, result)
			}
			if err != nil {
				t.Fatalf("EnrollIR returned error: %v", err)
			}
			if len(result.Chain) != 1 || !PublicKeysEqual(result.Chain[0].PublicKey, request.RequestedPrivateKey.Public()) {
				t.Fatal("issued IR certificate does not contain the requested public key")
			}
			if bodies := state.observedBodies(); !slices.Equal(bodies, []pkicmp.BodyType{pkicmp.BodyTypeIR, pkicmp.BodyTypeCertConf}) {
				t.Fatalf("expected IR and certConf, got %v", bodies)
			}
			if certReqID, observed := state.confirmation(); !observed || certReqID != 0 {
				t.Fatalf("expected certConf certReqId 0, got %d with observed %t", certReqID, observed)
			}
		})
	}
}

// TestEnrollIRImplicitConfirm verifies a granted implicit confirmation completes the IR without certConf.
func TestEnrollIRImplicitConfirm(t *testing.T) {
	pki := newTestPKI(t)
	server, state := newMockCMPServer(t, pki, testIRPassword, nil, mockOptions{GrantImplicitConfirm: true})
	defer server.Close()
	request := irEnrollmentRequest(t, pki, server.URL, false)
	request.ImplicitConfirm = true
	result, err := NewClient().EnrollIR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollIR returned error: %v", err)
	}
	if result.PendingConfirmation != nil || result.ExplicitConfirmation || len(result.Chain) != 1 {
		t.Fatal("expected an implicitly confirmed chain")
	}
	if state.count() != 1 {
		t.Fatalf("expected only the IR, got %d messages", state.count())
	}
}

// TestProtectedIRTemplate verifies the IR template repeats the CSR identity unchanged and carries
// only the fields RFC 9483 section 4.1.1 lists, with the requested notAfter when one is set.
func TestProtectedIRTemplate(t *testing.T) {
	pki := newTestPKI(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reordered := []byte{0x30, 0x22, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 'T', 'e', 's', 't', ' ', 'O', 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 'w', 'o', 'r', 'k', 'e', 'r'}
	for _, test := range []struct {
		name     string
		template x509.CertificateRequest
		want     []byte
	}{
		{name: "UTF8String subject keeps its order", template: x509.CertificateRequest{RawSubject: reordered, DNSNames: []string{"worker.example"}}, want: reordered},
		{name: "subjectAltName only", template: x509.CertificateRequest{DNSNames: []string{"worker.example"}}, want: []byte{0x30, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &test.template, key)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatal(err)
			}
			request := irEnrollmentRequest(t, pki, "https://example.test/cmp", false)
			request.CSRDER = csrDER
			request.RequestedPrivateKey = key
			credentials, err := credentialsFor(request.Protection)
			if err != nil {
				t.Fatal(err)
			}
			_, requestDER, err := protectedIR(request, csr, credentials)
			if err != nil {
				t.Fatalf("protectedIR returned error: %v", err)
			}
			// The proof of possession is verified over the encoding the server receives.
			message, err := pkicmp.ParsePKIMessage(requestDER)
			if err != nil {
				t.Fatal(err)
			}
			if message.Body.Type != pkicmp.BodyTypeIR || !bytes.Equal(message.Header.SenderKID, []byte("test-reference")) {
				t.Fatal("expected an IR carrying the PasswordBasedMac reference")
			}
			messages, err := message.Body.IR()
			if err != nil || len(*messages) != 1 {
				t.Fatalf("parse IR: %v", err)
			}
			certificateRequest := (*messages)[0]
			if err := pkicmp.VerifyPOP(&certificateRequest); err != nil {
				t.Fatalf("verify IR proof of possession: %v", err)
			}
			template := certificateRequest.CertReq.CertTemplate
			if certificateRequest.CertReq.CertReqID != 0 || len(certificateRequest.CertReq.Controls) != 0 {
				t.Fatal("expected certReqId 0 and no controls")
			}
			if !bytes.Equal(template.RawSubject, test.want) {
				t.Fatalf("expected template subject %x, got %x", test.want, template.RawSubject)
			}
			extensions, err := asn1.Marshal(csr.Extensions)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(template.Extensions, extensions) {
				t.Fatal("expected the CSR extensions in the template")
			}
			if template.Validity != nil || len(template.Issuer) != 0 || template.SerialNumber != nil {
				t.Fatal("expected no validity, issuer or serial number in the template")
			}
		})
	}

	t.Run("requested notAfter", func(t *testing.T) {
		request := irEnrollmentRequest(t, pki, "https://example.test/cmp", false)
		request.RequestedNotAfter = time.Date(2027, 1, 24, 12, 0, 0, 0, time.UTC)
		csr, err := x509.ParseCertificateRequest(request.CSRDER)
		if err != nil {
			t.Fatal(err)
		}
		credentials, err := credentialsFor(request.Protection)
		if err != nil {
			t.Fatal(err)
		}
		message, _, err := protectedIR(request, csr, credentials)
		if err != nil {
			t.Fatalf("protectedIR returned error: %v", err)
		}
		messages, err := message.Body.IR()
		if err != nil {
			t.Fatal(err)
		}
		validity := (*messages)[0].CertReq.CertTemplate.Validity
		if validity == nil || !validity.NotAfter.Equal(request.RequestedNotAfter) || !validity.NotBefore.IsZero() {
			t.Fatalf("expected only notAfter %s in the template validity, got %+v", request.RequestedNotAfter, validity)
		}
	})
}

// TestEnrollRequestsValidity verifies an IR and a KUR deliver the requested notAfter to the server.
func TestEnrollRequestsValidity(t *testing.T) {
	notAfter := time.Now().Add(720 * time.Hour).UTC().Truncate(time.Second)
	for _, test := range []struct {
		name   string
		enroll func(Client, EnrollmentRequest) (EnrollmentResult, error)
		build  func(*testing.T, testPKI, string) EnrollmentRequest
	}{
		{name: "IR", enroll: func(client Client, request EnrollmentRequest) (EnrollmentResult, error) {
			return client.EnrollIR(context.Background(), request)
		}, build: func(t *testing.T, pki testPKI, endpoint string) EnrollmentRequest {
			return irEnrollmentRequest(t, pki, endpoint, false)
		}},
		{name: "KUR", enroll: func(client Client, request EnrollmentRequest) (EnrollmentResult, error) {
			return client.EnrollKUR(context.Background(), request)
		}, build: func(t *testing.T, pki testPKI, endpoint string) EnrollmentRequest {
			request := kurEnrollmentRequest(t, pki, endpoint, true)
			request.ResponseCertReqID = nil
			return request
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			bootstrapRoots := x509.NewCertPool()
			bootstrapRoots.AddCert(pki.CACertificate)
			server, state := newMockCMPServer(t, pki, testIRPassword, bootstrapRoots, mockOptions{})
			defer server.Close()
			request := test.build(t, pki, server.URL)
			request.RequestedNotAfter = notAfter
			if _, err := test.enroll(NewClient(), request); err != nil {
				t.Fatalf("enrollment returned error: %v", err)
			}
			templates := state.receivedTemplates()
			if len(templates) != 1 || templates[0].Validity == nil || !templates[0].Validity.NotAfter.Equal(notAfter) || !templates[0].Validity.NotBefore.IsZero() {
				t.Fatalf("expected the server to receive notAfter %s only, got %+v", notAfter, templates)
			}
		})
	}
}

// TestEnrollIRRejectsInvalidIPShape verifies the fixed IR response identifier and body type are enforced.
func TestEnrollIRRejectsInvalidIPShape(t *testing.T) {
	pki := newTestPKI(t)
	server, _ := newMockCMPServer(t, pki, testIRPassword, nil, mockOptions{CertReqID: -1})
	defer server.Close()
	_, err := NewClient().EnrollIR(context.Background(), irEnrollmentRequest(t, pki, server.URL, false))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != testFailureCertReqIDMismatch {
		t.Fatalf("expected a certReqId mismatch, got %v", err)
	}

	cp, err := pkicmp.ParsePKIMessage(mustMarshal(t, pkicmp.NewPKIMessage(pkicmp.NewCPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{CertReqID: 0, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}}}}), pkicmp.MessageOptions{})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = extractEnrollmentResponse(cp, EnrollmentRequest{Operation: OperationIR})
	if !errors.As(err, &typed) || typed.Failure != "unsupportedBody" {
		t.Fatalf("expected a CP answer to an IR to be refused, got %v", err)
	}
}

// mustMarshal encodes a PKIMessage or fails the test.
func mustMarshal(t *testing.T, message *pkicmp.PKIMessage) []byte {
	t.Helper()
	der, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestEnrollIRRefusesWrongPublicKey verifies an issued certificate for another key is refused in certConf.
func TestEnrollIRRefusesWrongPublicKey(t *testing.T) {
	pki := newTestPKI(t)
	server, state := newMockCMPServer(t, pki, testIRPassword, nil, mockOptions{WrongPublicKey: true})
	defer server.Close()
	_, err := NewClient().EnrollIR(context.Background(), irEnrollmentRequest(t, pki, server.URL, false))
	var typed *Error
	if !errors.As(err, &typed) || typed.Failure != testFailurePublicKeyMismatch {
		t.Fatalf("expected a public key mismatch, got %v", err)
	}
	status, _, observed := state.confirmationDetail()
	if !observed || status.StatusInfo == nil || status.StatusInfo.Status != pkicmp.StatusRejection {
		t.Fatal("expected the refused certificate to be rejected in certConf")
	}
}

// TestValidateIRRequestRejectsInvalidProofs verifies the requested key and the CSR are checked before any send.
func TestValidateIRRequestRejectsInvalidProofs(t *testing.T) {
	pki := newTestPKI(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*EnrollmentRequest)
	}{
		{name: "missing requested key", mutate: func(request *EnrollmentRequest) { request.RequestedPrivateKey = nil }},
		{name: "requested key differs from the CSR", mutate: func(request *EnrollmentRequest) { request.RequestedPrivateKey = otherKey }},
		{name: "invalid CSR signature", mutate: func(request *EnrollmentRequest) {
			request.CSRDER = append([]byte(nil), request.CSRDER...)
			request.CSRDER[len(request.CSRDER)-1] ^= 0xff
		}},
		{name: "no protection", mutate: func(request *EnrollmentRequest) { request.Protection = Protection{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := irEnrollmentRequest(t, pki, "https://example.test/cmp", false)
			test.mutate(&request)
			var typed *Error
			if err := ValidateIRRequest(request); !errors.As(err, &typed) || typed.Kind != ErrorKindPermanent {
				t.Fatalf("expected a permanent validation failure, got %v", err)
			}
		})
	}
}

// TestPollIRUntilIssued verifies a deferred IR is collected by polling and confirmed.
func TestPollIRUntilIssued(t *testing.T) {
	pki := newTestPKI(t)
	pollInterval := 20 * time.Millisecond
	endpoint, _ := newDeferredCMPServer(t, pki, testIRPassword, 1, pollInterval)
	defer endpoint.Close()
	request := irEnrollmentRequest(t, pki, endpoint.URL, false)
	request.Sender = &pkix.Name{CommonName: "cmp-issuer-ir-test"}
	client := NewClient()
	result, err := client.EnrollIR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollIR returned error: %v", err)
	}
	for polls := 0; result.Pending != nil; polls++ {
		if polls > 3 {
			t.Fatal("the IR did not complete within the expected number of polls")
		}
		if result.Pending.CertReqID != 0 {
			t.Fatalf("expected the pending IR to use certReqId 0, got %d", result.Pending.CertReqID)
		}
		time.Sleep(max(result.Pending.CheckAfter, 2*pollInterval))
		result, err = client.PollP10CR(context.Background(), PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner, RequestNonce: result.Pending.RequestNonce})
		if err != nil {
			t.Fatalf("poll returned error: %v", err)
		}
	}
	result, err = confirmToCompletion(t, client, request, result)
	if err != nil {
		t.Fatalf("confirmation returned error: %v", err)
	}
	if !result.ExplicitConfirmation || !PublicKeysEqual(result.Chain[0].PublicKey, request.RequestedPrivateKey.Public()) {
		t.Fatal("expected an explicitly confirmed certificate for the requested key")
	}
}
