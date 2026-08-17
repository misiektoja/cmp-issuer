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

package protocol

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// Names used by the response sender comparison tests, modelled on a CA whose subject carries a UID.
const (
	testAuthorityCN = "ManagementCA"
	testAuthorityO  = "Example Container Quickstart"
)

// testPKI contains ephemeral credentials used by one protocol test.
type testPKI struct {
	CAKey                crypto.Signer
	CACertificate        *x509.Certificate
	BootstrapKey         crypto.Signer
	BootstrapCertificate *x509.Certificate
}

// mockOptions selects negative response behavior for the mock CMP server.
type mockOptions struct {
	CertReqID           int64
	WrongPublicKey      bool
	InvalidProtection   bool
	WrongTransactionID  bool
	WrongNonce          bool
	ImpostorAuthority   bool
	MismatchedSenderKID bool
	OmitPKIConfCerts    bool
	InvalidPKIConf      bool
	HTTPStatus          int
	ContentType         string
}

// mockState records authenticated request bodies observed by the mock server.
type mockState struct {
	mu                    sync.Mutex
	bodyTypes             []pkicmp.BodyType
	confirmationCertReqID int64
	confirmationObserved  bool
}

// add records one request body type.
func (s *mockState) add(bodyType pkicmp.BodyType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodyTypes = append(s.bodyTypes, bodyType)
}

// count returns the number of recorded requests.
func (s *mockState) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodyTypes)
}

// recordConfirmation records the certReqId sent in certConf.
func (s *mockState) recordConfirmation(certReqID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confirmationCertReqID = certReqID
	s.confirmationObserved = true
}

// confirmation returns the recorded certConf identifier.
func (s *mockState) confirmation() (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmationCertReqID, s.confirmationObserved
}

// newTestPKI creates an ECDSA root, bootstrap key and bootstrap certificate.
func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CMP Test Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true, SubjectKeyId: []byte{1, 2, 3}}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CMP Bootstrap"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{4, 5, 6}}
	bootstrapDER, err := x509.CreateCertificate(rand.Reader, bootstrapTemplate, caCertificate, bootstrapKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapCertificate, err := x509.ParseCertificate(bootstrapDER)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{CAKey: caKey, CACertificate: caCertificate, BootstrapKey: bootstrapKey, BootstrapCertificate: bootstrapCertificate}
}

// newSubordinateAuthority issues a CA certificate under the test root so it chains to the same trust anchor.
func newSubordinateAuthority(t *testing.T, pki testPKI, commonName string) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true, SubjectKeyId: []byte{7, 8, 9}}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.CACertificate, key.Public(), pki.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

// createCSR creates a signed DER CSR and returns its private key.
func createCSR(t *testing.T, commonName string) ([]byte, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{"test.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return requestDER, key
}

// issueLeaf creates a leaf certificate containing the CSR identity and selected public key.
func issueLeaf(t *testing.T, pki testPKI, request *x509.CertificateRequest, publicKey any) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: request.Subject, DNSNames: request.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, pki.CACertificate, publicKey, pki.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// newMockCMPServer creates a protected two-message P10CR and certConf test server.
func newMockCMPServer(t *testing.T, pki testPKI, password []byte, bootstrapRoots *x509.CertPool, options mockOptions) (*httptest.Server, *mockState) {
	t.Helper()
	state := &mockState{}
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
		verifyOptions := pkicmp.VerifyOptions{SharedSecret: password, TrustPool: bootstrapRoots, ExtraCerts: message.ExtraCerts, SenderKID: message.Header.SenderKID}
		if _, err := message.Verify(verifyOptions); err != nil {
			t.Errorf("verify request protection: %v", err)
			return
		}
		state.add(message.Body.Type)
		response := &pkicmp.PKIMessage{Header: pkicmp.PKIHeader{PVNO: pkicmp.PVNO2, Sender: pkicmp.NewDirectoryName(pki.CACertificate.Subject), TransactionID: append([]byte(nil), message.Header.TransactionID...), RecipNonce: append([]byte(nil), message.Header.SenderNonce...)}}
		switch message.Body.Type {
		case pkicmp.BodyTypeP10CR:
			certificateRequest, parseErr := message.Body.P10CR()
			if parseErr != nil {
				t.Errorf("parse P10CR: %v", parseErr)
				return
			}
			publicKey := certificateRequest.PublicKey
			if options.WrongPublicKey {
				_, wrongKey := createCSR(t, "wrong")
				publicKey = wrongKey.Public()
			}
			leaf := issueLeaf(t, pki, certificateRequest, publicKey)
			response.Body = pkicmp.NewCPBody(&pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{CertReqID: options.CertReqID, Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted}, CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{Certificate: &pkicmp.CMPCertificate{Raw: leaf.Raw}}}}}})
		case pkicmp.BodyTypeCertConf:
			confirmation, parseErr := message.Body.CertConf()
			if parseErr != nil || len(*confirmation) != 1 {
				t.Errorf("parse certConf: %v", parseErr)
				return
			}
			state.recordConfirmation((*confirmation)[0].CertReqID)
			response.Body = pkicmp.NewPKIConfBody()
		default:
			t.Errorf("unexpected request body %s", message.Body.Type)
			return
		}
		if options.WrongTransactionID {
			response.Header.TransactionID = []byte("wrong-transaction")
		}
		if options.WrongNonce {
			response.Header.RecipNonce = []byte("wrong-nonce")
		}
		signingCertificate := pki.CACertificate
		signingKey := pki.CAKey
		if options.ImpostorAuthority {
			// A subordinate authority under the same trust anchor, naming itself in the header. Its
			// signature verifies and its sender matches its own subject, so only the recipient
			// comparison can reject it.
			impostorKey, impostorCertificate := newSubordinateAuthority(t, pki, "CMP Test Impostor CA")
			signingCertificate = impostorCertificate
			signingKey = impostorKey
			response.Header.Sender = pkicmp.NewDirectoryName(impostorCertificate.Subject)
		}
		if options.MismatchedSenderKID {
			copyCertificate := *signingCertificate
			copyCertificate.SubjectKeyId = []byte{9, 9, 9}
			signingCertificate = &copyCertificate
		}
		credentials, err := pkicmp.NewSignatureCredentials(signingKey, signingCertificate)
		if err != nil {
			t.Errorf("create response credentials: %v", err)
			return
		}
		if err := credentials.Protect(response); err != nil {
			t.Errorf("protect response: %v", err)
			return
		}
		if message.Body.Type == pkicmp.BodyTypeCertConf && options.OmitPKIConfCerts {
			response.ExtraCerts = nil
		}
		if options.InvalidProtection {
			response.Protection[0] ^= 0xff
		}
		if message.Body.Type == pkicmp.BodyTypeCertConf && options.InvalidPKIConf {
			response.Protection[0] ^= 0xff
		}
		responseDER, err := response.MarshalBinary()
		if err != nil {
			t.Errorf("marshal response: %v", err)
			return
		}
		contentType := options.ContentType
		if contentType == "" {
			contentType = "application/pkixcmp"
		}
		writer.Header().Set("Content-Type", contentType)
		status := options.HTTPStatus
		if status == 0 {
			status = http.StatusOK
		}
		writer.WriteHeader(status)
		_, _ = writer.Write(responseDER)
	}))
	return server, state
}

// baseEnrollmentRequest creates common trusted P10CR test input without a pinned response identifier.
// The transaction identifier is pinned because confirming an issued certificate is a separate call
// that has to name the transaction it completes.
func baseEnrollmentRequest(t *testing.T, pki testPKI, endpoint string) EnrollmentRequest {
	t.Helper()
	csrDER, _ := createCSR(t, "cmp-issuer-test")
	trust := x509.NewCertPool()
	trust.AddCert(pki.CACertificate)
	transactionID := make([]byte, 16)
	if _, err := rand.Read(transactionID); err != nil {
		t.Fatalf("generate transaction ID: %v", err)
	}
	return EnrollmentRequest{EndpointURL: endpoint, Timeout: 5 * time.Second, MaxResponseSize: 1 << 20, Recipient: pki.CACertificate.Subject, CSRDER: csrDER, CMPTrust: trust, RejectGrantedMods: true, TransactionID: transactionID}
}

// pinCertReqID returns a pinned P10CR response identifier.
func pinCertReqID(value int64) *int64 { return &value }

// enrollAndConfirm runs one enrollment to completion the way the signer does, by confirming the
// issued certificate through separate calls until the server answers pkiConf. Confirmation is a
// caller-driven step so that the chain can be recorded before certConf reaches the network.
func enrollAndConfirm(t *testing.T, request EnrollmentRequest) (EnrollmentResult, error) {
	t.Helper()
	client := NewClient()
	result, err := client.EnrollP10CR(context.Background(), request)
	if err != nil {
		return result, err
	}
	return confirmToCompletion(t, client, request, result)
}

// confirmToCompletion drives the confirmation exchange of an already issued certificate to its end.
func confirmToCompletion(t *testing.T, client Client, request EnrollmentRequest, result EnrollmentResult) (EnrollmentResult, error) {
	t.Helper()
	chain := result.Chain
	for pending := result.PendingConfirmation; pending != nil; {
		confirmed, err := client.ConfirmP10CR(context.Background(), ConfirmRequest{Enrollment: request, Certificate: chain[0], CertReqID: pending.CertReqID, RecipNonce: pending.RecipNonce, ResponseSigner: pending.ResponseSigner, RequestNonce: pending.RequestNonce})
		if err != nil {
			return EnrollmentResult{}, err
		}
		if confirmed.PendingConfirmation == nil {
			return EnrollmentResult{Chain: chain, ExtraCertificateCount: result.ExtraCertificateCount, ExplicitConfirmation: confirmed.ExplicitConfirmation, ResponseCertReqID: confirmed.ResponseCertReqID}, nil
		}
		pending = confirmed.PendingConfirmation
	}
	return result, nil
}

// TestEnrollP10CRAcceptsInteroperableCertReqIDs verifies both interoperable identifiers are accepted and echoed by default.
func TestEnrollP10CRAcceptsInteroperableCertReqIDs(t *testing.T) {
	for _, certReqID := range []int64{ResponseCertReqIDStandard, ResponseCertReqIDLegacyZero} {
		t.Run(fmt.Sprintf("certReqId %d", certReqID), func(t *testing.T) {
			pki := newTestPKI(t)
			password := []byte("test-shared-secret")
			server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: certReqID})
			defer server.Close()
			request := baseEnrollmentRequest(t, pki, server.URL)
			request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
			if _, err := enrollAndConfirm(t, request); err != nil {
				t.Fatalf("EnrollP10CR returned error: %v", err)
			}
			if echoed, observed := state.confirmation(); !observed || echoed != certReqID {
				t.Fatalf("expected certConf certReqId %d, got %d with observed %t", certReqID, echoed, observed)
			}
		})
	}
}

// TestEnrollP10CRPinnedLegacyZeroCertReqID verifies an explicit legacy pin is echoed in certConf.
func TestEnrollP10CRPinnedLegacyZeroCertReqID(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: 0})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.ResponseCertReqID = pinCertReqID(ResponseCertReqIDLegacyZero)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	if _, err := enrollAndConfirm(t, request); err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if certReqID, observed := state.confirmation(); !observed || certReqID != 0 {
		t.Fatalf("expected certConf certReqId 0, got %d with observed %t", certReqID, observed)
	}
}

// TestEnrollP10CRPasswordBasedMac verifies protected P10CR, CP, certConf and pkiConf exchange.
func TestEnrollP10CRPasswordBasedMac(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: -1, HTTPStatus: http.StatusBadRequest})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	result, err := enrollAndConfirm(t, request)
	if err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if len(result.Chain) != 1 || state.count() != 2 {
		t.Fatalf("expected one leaf and two CMP messages, got %d and %d", len(result.Chain), state.count())
	}
}

// TestEnrollP10CRSignatureProtection verifies bootstrap protection does not use the requested private key.
func TestEnrollP10CRSignatureProtection(t *testing.T) {
	pki := newTestPKI(t)
	bootstrapRoots := x509.NewCertPool()
	bootstrapRoots.AddCert(pki.CACertificate)
	server, state := newMockCMPServer(t, pki, nil, bootstrapRoots, mockOptions{CertReqID: -1, MismatchedSenderKID: true, OmitPKIConfCerts: true})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Signature = &SignatureProtection{PrivateKey: pki.BootstrapKey, Certificate: pki.BootstrapCertificate, Chain: []*x509.Certificate{pki.CACertificate}}
	if _, err := enrollAndConfirm(t, request); err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if state.count() != 2 {
		t.Fatalf("expected P10CR and certConf, got %d messages", state.count())
	}
}

// TestEnrollP10CRRejectsInvalidPKIConfWithRememberedSigner verifies signer reuse does not weaken confirmation protection.
func TestEnrollP10CRRejectsInvalidPKIConfWithRememberedSigner(t *testing.T) {
	pki := newTestPKI(t)
	bootstrapRoots := x509.NewCertPool()
	bootstrapRoots.AddCert(pki.CACertificate)
	server, _ := newMockCMPServer(t, pki, nil, bootstrapRoots, mockOptions{CertReqID: -1, OmitPKIConfCerts: true, InvalidPKIConf: true})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Signature = &SignatureProtection{PrivateKey: pki.BootstrapKey, Certificate: pki.BootstrapCertificate, Chain: []*x509.Certificate{pki.CACertificate}}
	_, err := enrollAndConfirm(t, request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != "badMessageCheck" {
		t.Fatalf("expected protected pkiConf rejection, got %v", err)
	}
}

// TestEnrollP10CRRejectsSecurityFailures verifies independent negative transaction checks.
func TestEnrollP10CRRejectsSecurityFailures(t *testing.T) {
	tests := []struct {
		name    string
		options mockOptions
		pinned  *int64
		failure string
	}{
		{name: "pinned certReqId", options: mockOptions{CertReqID: 0}, pinned: pinCertReqID(ResponseCertReqIDStandard), failure: "certReqIdMismatch"},
		{name: "unsupported certReqId", options: mockOptions{CertReqID: 7}, failure: "certReqIdUnsupported"},
		{name: "public key", options: mockOptions{CertReqID: -1, WrongPublicKey: true}, failure: "publicKeyMismatch"},
		{name: "protection", options: mockOptions{CertReqID: -1, InvalidProtection: true}, failure: "badMessageCheck"},
		{name: "transaction", options: mockOptions{CertReqID: -1, WrongTransactionID: true}, failure: "transactionIdMismatch"},
		{name: "nonce", options: mockOptions{CertReqID: -1, WrongNonce: true}, failure: "nonceMismatch"},
		{name: "impostor authority", options: mockOptions{CertReqID: -1, ImpostorAuthority: true}, failure: "wrongAuthority"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			password := []byte("test-shared-secret")
			server, _ := newMockCMPServer(t, pki, password, nil, test.options)
			defer server.Close()
			request := baseEnrollmentRequest(t, pki, server.URL)
			request.ResponseCertReqID = test.pinned
			request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
			_, err := NewClient().EnrollP10CR(context.Background(), request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != test.failure {
				t.Fatalf("expected security failure %s, got %v", test.failure, err)
			}
		})
	}
}

// TestSendCMPRejectsRedirect verifies redirect targets cannot alter transaction flow.
func TestSendCMPRejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("redirect target was contacted") }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	request := EnrollmentRequest{Timeout: time.Second}
	_, err := sendCMP(context.Background(), newHTTPClient(request), redirect.URL, []byte{1}, 1024)
	var typed *Error
	if !errors.As(err, &typed) || typed.Failure != "redirectRejected" {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

// TestParseCertificateRequestDERPreservesCSR verifies PEM decoding returns the signed DER unchanged.
func TestParseCertificateRequestDERPreservesCSR(t *testing.T) {
	requestDER, _ := createCSR(t, "preserved")
	requestPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
	parsed, err := ParseCertificateRequestDER(requestPEM)
	if err != nil || !bytes.Equal(parsed, requestDER) {
		t.Fatalf("CSR was not preserved: %v", err)
	}
}

// TestRefusedRetransmissionsFailPermanently covers the answers NCM 26.7 and EJBCA CE 9.3.7 return to
// an enrollment repeated under a transaction identifier the server already answered. Neither replays
// the certificate it issued, so the attempt cannot succeed and must fail under the reported reason.
func TestRefusedRetransmissionsFailPermanently(t *testing.T) {
	for name, failInfo := range map[string]pkicmp.PKIFailureInfo{
		"NCM reports the transaction identifier is in use": pkicmp.FailTransactionIdInUse,
		"EJBCA reports the end entity already generated":   pkicmp.FailBadRequest,
	} {
		t.Run(name, func(t *testing.T) {
			err := classifyStatus(pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: failInfo})
			var classified *Error
			if !errors.As(err, &classified) {
				t.Fatalf("expected a classified protocol error, got %v", err)
			}
			if classified.Kind != ErrorKindPermanent {
				t.Fatalf("expected a permanent failure, got %s", classified.Kind)
			}
			if classified.Failure != failInfo.String() {
				t.Fatalf("expected the failure to report %q, got %q", failInfo.String(), classified.Failure)
			}
		})
	}
}

// TestSenderMatchesRecipientIgnoresAttributeOrder covers the response sender comparison. A recipient
// is configured as text and re-encoded by Go, while the sender arrives in whatever order the server
// encoded it, so the two agree on content far more often than on order.
func TestSenderMatchesRecipientIgnoresAttributeOrder(t *testing.T) {
	recipient, err := ParseDistinguishedName("UID=c-0o1uffqidnca67k8g,CN=" + testAuthorityCN + ",O=" + testAuthorityO)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	reversed := pkix.RDNSequence{
		{{Type: oidUserID, Value: "c-0o1uffqidnca67k8g"}},
		{{Type: []int{2, 5, 4, 3}, Value: testAuthorityCN}},
		{{Type: []int{2, 5, 4, 10}, Value: testAuthorityO}},
	}
	if !senderMatchesRecipient(pkicmp.GeneralName{DirectoryName: reversed}, recipient) {
		t.Error("a sender carrying the configured attributes in encoded order should be accepted")
	}
}

// TestSenderMatchesRecipientRejectsAnotherAuthority covers the case the comparison exists for.
func TestSenderMatchesRecipientRejectsAnotherAuthority(t *testing.T) {
	recipient, err := ParseDistinguishedName("CN=" + testAuthorityCN + ",O=" + testAuthorityO)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	other := pkicmp.NewDirectoryName(pkix.Name{CommonName: "Some Other CA", Organization: []string{testAuthorityO}})
	if senderMatchesRecipient(other, recipient) {
		t.Error("a sender naming a different authority should be rejected")
	}
	extra := pkicmp.NewDirectoryName(pkix.Name{CommonName: testAuthorityCN, Organization: []string{testAuthorityO}, Country: []string{"DE"}})
	if senderMatchesRecipient(extra, recipient) {
		t.Error("a sender carrying an attribute the recipient does not have should be rejected")
	}
}

// TestSenderMatchesRecipientAcceptsAbsentName covers the RFC 4210 section 5.1.1 NULL DN, which carries
// no name to compare, and a recipient the issuer left unset.
func TestSenderMatchesRecipientAcceptsAbsentName(t *testing.T) {
	recipient, err := ParseDistinguishedName("CN=" + testAuthorityCN)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	if !senderMatchesRecipient(pkicmp.GeneralName{}, recipient) {
		t.Error("a NULL DN sender should be accepted")
	}
	if !senderMatchesRecipient(pkicmp.NewDirectoryName(pkix.Name{CommonName: testAuthorityCN}), pkix.Name{}) {
		t.Error("an unset recipient should not reject a named sender")
	}
}
