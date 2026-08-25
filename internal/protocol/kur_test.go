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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// kurEnrollmentRequest creates a valid certificate-authenticated renewal request with selectable key rotation.
func kurEnrollmentRequest(t *testing.T, pki testPKI, endpoint string, rotateKey bool) EnrollmentRequest {
	t.Helper()
	currentCSRDER, currentKey := createCSR(t, "cmp-issuer-kur-test")
	currentCSR, err := x509.ParseCertificateRequest(currentCSRDER)
	if err != nil {
		t.Fatal(err)
	}
	currentCertificate := issueLeaf(t, pki, currentCSR, currentKey.Public())
	requestedKey := currentKey
	if rotateKey {
		requestedKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: currentCSR.Subject, DNSNames: currentCSR.DNSNames}, requestedKey)
	if err != nil {
		t.Fatal(err)
	}
	request := baseEnrollmentRequest(t, pki, endpoint)
	request.Operation = OperationKUR
	request.CSRDER = requestDER
	request.RequestedPrivateKey = requestedKey
	request.ResponseCertReqID = pinCertReqID(ResponseCertReqIDLegacyZero)
	request.Protection.Signature = &SignatureProtection{PrivateKey: currentKey, Certificate: currentCertificate, Chain: []*x509.Certificate{pki.CACertificate}}
	return request
}

// TestEnrollKUR verifies new-key and same-key updates use CRMF POP, KUP and the standard identifier.
func TestEnrollKUR(t *testing.T) {
	for _, test := range []struct {
		name      string
		rotateKey bool
	}{
		{name: "new key", rotateKey: true},
		{name: "same key", rotateKey: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			bootstrapRoots := x509.NewCertPool()
			bootstrapRoots.AddCert(pki.CACertificate)
			server, state := newMockCMPServer(t, pki, nil, bootstrapRoots, mockOptions{CertReqID: ResponseCertReqIDLegacyZero})
			defer server.Close()
			request := kurEnrollmentRequest(t, pki, server.URL, test.rotateKey)
			client := NewClient()
			result, err := client.EnrollKUR(context.Background(), request)
			if err == nil {
				result, err = confirmToCompletion(t, client, request, result)
			}
			if err != nil {
				t.Fatalf("EnrollKUR returned error: %v", err)
			}
			if len(result.Chain) != 1 || !PublicKeysEqual(result.Chain[0].PublicKey, request.RequestedPrivateKey.Public()) {
				t.Fatal("issued KUR certificate does not contain the requested public key")
			}
			if state.count() != 2 {
				t.Fatalf("expected KUR and certConf, got %d messages", state.count())
			}
			if certReqID, observed := state.confirmation(); !observed || certReqID != ResponseCertReqIDLegacyZero {
				t.Fatalf("expected certConf certReqId 0, got %d with observed %t", certReqID, observed)
			}
		})
	}
}

// TestEnrollKURRejectsInvalidKUPShape verifies the fixed KUR response identifier is enforced.
func TestEnrollKURRejectsInvalidKUPShape(t *testing.T) {
	for _, test := range []struct {
		name    string
		options mockOptions
		kind    ErrorKind
		failure string
	}{
		{name: "nonzero certReqId", options: mockOptions{CertReqID: 7}, kind: ErrorKindSecurity, failure: testFailureCertReqIDMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			bootstrapRoots := x509.NewCertPool()
			bootstrapRoots.AddCert(pki.CACertificate)
			server, _ := newMockCMPServer(t, pki, nil, bootstrapRoots, test.options)
			defer server.Close()
			_, err := NewClient().EnrollKUR(context.Background(), kurEnrollmentRequest(t, pki, server.URL, true))
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != test.kind || typed.Failure != test.failure {
				t.Fatalf("expected %s %s failure, got %v", test.kind, test.failure, err)
			}
		})
	}
}

// TestEnrollKURAcceptsCAPubsByDefault verifies interoperable KUP handling deduplicates chain candidates.
func TestEnrollKURAcceptsCAPubsByDefault(t *testing.T) {
	pki := newTestPKI(t)
	bootstrapRoots := x509.NewCertPool()
	bootstrapRoots.AddCert(pki.CACertificate)
	server, _ := newMockCMPServer(t, pki, nil, bootstrapRoots, mockOptions{CertReqID: ResponseCertReqIDLegacyZero, KUPCAPubs: true})
	defer server.Close()
	request := kurEnrollmentRequest(t, pki, server.URL, true)
	result, err := NewClient().EnrollKUR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollKUR returned error: %v", err)
	}
	if result.ExtraCertificateCount != 1 {
		t.Fatalf("expected duplicate caPubs and extraCerts certificates to produce one candidate, got %d", result.ExtraCertificateCount)
	}
}

// TestEnrollKURCanRequireAbsentCAPubs verifies the focused strict option rejects a nonconforming KUP.
func TestEnrollKURCanRequireAbsentCAPubs(t *testing.T) {
	pki := newTestPKI(t)
	bootstrapRoots := x509.NewCertPool()
	bootstrapRoots.AddCert(pki.CACertificate)
	server, _ := newMockCMPServer(t, pki, nil, bootstrapRoots, mockOptions{CertReqID: ResponseCertReqIDLegacyZero, KUPCAPubs: true})
	defer server.Close()
	request := kurEnrollmentRequest(t, pki, server.URL, true)
	request.RequireKUPCAPubsAbsent = true
	_, err := NewClient().EnrollKUR(context.Background(), request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindPermanent || typed.Failure != "badDataFormat" {
		t.Fatalf("expected strict KUP caPubs rejection, got %v", err)
	}
}

// TestResponseCandidatesDoNotExtendTrust verifies response certificates cannot become trust anchors.
func TestResponseCandidatesDoNotExtendTrust(t *testing.T) {
	pki := newTestPKI(t)
	csrDER, key := createCSR(t, "untrusted-candidate")
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, pki, csr, key.Public())
	if _, err := validateAndOrderChain(leaf, []*x509.Certificate{pki.CACertificate}, x509.NewCertPool()); err == nil {
		t.Fatal("expected an untrusted response candidate not to become a root")
	}
}

// TestValidateKURRequestRejectsInvalidProofs verifies both private keys and the unchanged identity are enforced locally.
func TestValidateKURRequestRejectsInvalidProofs(t *testing.T) {
	pki := newTestPKI(t)
	valid := kurEnrollmentRequest(t, pki, "https://cmp.example.test", true)
	differentCSRDER, differentKey := createCSR(t, "different-subject")
	differentSANCSRDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: valid.Protection.Signature.Certificate.Subject, DNSNames: []string{"different.example"}}, valid.RequestedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	differentProtectionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		mutate  func(*EnrollmentRequest)
		failure string
	}{
		{name: "password protection", mutate: func(request *EnrollmentRequest) {
			request.Protection = Protection{Password: &PasswordProtection{Reference: []byte("id"), Secret: []byte("secret")}}
		}, failure: "badRequest"},
		{name: "requested key mismatch", mutate: func(request *EnrollmentRequest) { request.RequestedPrivateKey = differentKey }, failure: "badPOP"},
		{name: "protection key mismatch", mutate: func(request *EnrollmentRequest) { request.Protection.Signature.PrivateKey = differentProtectionKey }, failure: "badRequest"},
		{name: "expired certificate", mutate: func(request *EnrollmentRequest) {
			certificate := *request.Protection.Signature.Certificate
			certificate.NotAfter = time.Now().Add(-time.Minute)
			request.Protection.Signature.Certificate = &certificate
		}, failure: "badTime"},
		{name: "digital signature prohibited", mutate: func(request *EnrollmentRequest) {
			certificate := *request.Protection.Signature.Certificate
			certificate.KeyUsage = x509.KeyUsageKeyEncipherment
			request.Protection.Signature.Certificate = &certificate
		}, failure: "badAlg"},
		{name: "changed subject", mutate: func(request *EnrollmentRequest) {
			request.CSRDER = differentCSRDER
			request.RequestedPrivateKey = differentKey
		}, failure: "badCertTemplate"},
		{name: "changed SAN", mutate: func(request *EnrollmentRequest) { request.CSRDER = differentSANCSRDER }, failure: "badCertTemplate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			protection := *valid.Protection.Signature
			request.Protection.Signature = &protection
			test.mutate(&request)
			err := ValidateKURRequest(request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != ErrorKindPermanent || typed.Failure != test.failure {
				t.Fatalf("expected permanent %s failure, got %v", test.failure, err)
			}
		})
	}
}
