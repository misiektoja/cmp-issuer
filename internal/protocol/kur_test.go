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
	"math/big"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// currentCertificateValidity returns the validity of a certificate that a KUR updates. It starts before
// the certificates the test servers issue, so an updated certificate never repeats it.
func currentCertificateValidity() (time.Time, time.Time) {
	return time.Now().Add(-30 * time.Minute), time.Now().Add(30 * time.Minute)
}

// kurEnrollmentRequest creates a valid certificate-authenticated renewal request with selectable key rotation.
func kurEnrollmentRequest(t *testing.T, pki testPKI, endpoint string, rotateKey bool) EnrollmentRequest {
	t.Helper()
	currentCSRDER, currentKey := createCSR(t, "cmp-issuer-kur-test")
	currentCSR, err := x509.ParseCertificateRequest(currentCSRDER)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := currentCertificateValidity()
	currentCertificate := issueLeafWithValidity(t, pki, currentCSR, currentKey.Public(), notBefore, notAfter)
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

// keyRotationCases names the new-key and same-key variants that every KUR test covers.
var keyRotationCases = []struct {
	name      string
	rotateKey bool
}{
	{name: "new key", rotateKey: true},
	{name: "same key", rotateKey: false},
}

// TestEnrollKUR verifies new-key and same-key updates use CRMF POP, KUP and the standard identifier.
func TestEnrollKUR(t *testing.T) {
	for _, test := range keyRotationCases {
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

// TestProtectedKURIncludesOldCertID verifies each update identifies the exact existing certificate.
func TestProtectedKURIncludesOldCertID(t *testing.T) {
	pki := newTestPKI(t)
	request := kurEnrollmentRequest(t, pki, "https://cmp.example.test", false)
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := credentialsFor(request.Protection)
	if err != nil {
		t.Fatal(err)
	}
	_, encoded, err := protectedKUR(request, csr, credentials)
	if err != nil {
		t.Fatal(err)
	}
	message, err := pkicmp.ParsePKIMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := message.Body.KUR()
	if err != nil || messages == nil || len(*messages) != 1 {
		t.Fatalf("parse KUR controls: %v", err)
	}
	controls := (*messages)[0].CertReq.Controls
	if len(controls) != 1 || controls[0].Type.String() != "1.3.6.1.5.5.7.5.1.5" {
		t.Fatalf("expected one oldCertID control, got %+v", controls)
	}
	var oldCertID struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	rest, err := asn1.Unmarshal(controls[0].Value, &oldCertID)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decode oldCertID: %v", err)
	}
	current := request.Protection.Signature.Certificate
	if oldCertID.Issuer.Class != asn1.ClassContextSpecific || oldCertID.Issuer.Tag != 4 || !oldCertID.Issuer.IsCompound || !bytes.Equal(oldCertID.Issuer.Bytes, current.RawIssuer) {
		t.Fatal("oldCertID does not preserve the current certificate issuer")
	}
	if oldCertID.SerialNumber == nil || oldCertID.SerialNumber.Cmp(current.SerialNumber) != 0 {
		t.Fatalf("oldCertID serial %v does not identify current serial %v", oldCertID.SerialNumber, current.SerialNumber)
	}
}

// kurSubjectCase is a certificate subject that an encoded pkix.Name does not reproduce.
type kurSubjectCase struct {
	name string
	// rawSubject is the subject of the certificate being updated, empty when nil.
	rawSubject []byte
	// csrSubject names the same attributes in the CSR.
	csrSubject pkix.Name
	// want is the subject DER the KUR template must carry.
	want []byte
}

// kurSubjectCases returns a reordered UTF8String subject and the NULL-DN of a certificate named only in subjectAltName.
func kurSubjectCases(t *testing.T) []kurSubjectCase {
	t.Helper()
	reordered, name := reorderedSubject(t, "cmp-issuer-kur-test")
	return []kurSubjectCase{
		{name: "reordered UTF8String subject", rawSubject: reordered, csrSubject: name, want: reordered},
		{name: "subjectAltName only", csrSubject: pkix.Name{}, want: []byte{0x30, 0x00}},
	}
}

// kurRequestForSubject returns a same-key KUR request for a certificate with the subject of test.
func kurRequestForSubject(t *testing.T, pki testPKI, endpoint string, test kurSubjectCase) EnrollmentRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := certificateWithRawSubject(t, pki, test.rawSubject, key)
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: test.csrSubject, DNSNames: certificate.DNSNames}, key)
	if err != nil {
		t.Fatal(err)
	}
	request := baseEnrollmentRequest(t, pki, endpoint)
	request.Operation = OperationKUR
	request.CSRDER = requestDER
	request.RequestedPrivateKey = key
	request.ResponseCertReqID = pinCertReqID(ResponseCertReqIDLegacyZero)
	request.Protection.Signature = &SignatureProtection{PrivateKey: key, Certificate: certificate, Chain: []*x509.Certificate{pki.CACertificate}}
	if err := ValidateKURRequest(request); err != nil {
		t.Fatalf("ValidateKURRequest returned error: %v", err)
	}
	return request
}

// TestProtectedKURKeepsCertificateSubject verifies the template subject and the sender repeat the subject
// of the certificate being updated without modification, as RFC 9483 sections 3.1 and 4.1.3 require.
func TestProtectedKURKeepsCertificateSubject(t *testing.T) {
	for _, test := range kurSubjectCases(t) {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			request := kurRequestForSubject(t, pki, "https://cmp.example.test", test)
			csr, err := x509.ParseCertificateRequest(request.CSRDER)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := credentialsFor(request.Protection)
			if err != nil {
				t.Fatal(err)
			}
			_, encoded, err := protectedKUR(request, csr, credentials)
			if err != nil {
				t.Fatal(err)
			}
			message, err := pkicmp.ParsePKIMessage(encoded)
			if err != nil {
				t.Fatal(err)
			}
			messages, err := message.Body.KUR()
			if err != nil || messages == nil || len(*messages) != 1 {
				t.Fatalf("parse KUR: %v", err)
			}
			if subject := (*messages)[0].CertReq.CertTemplate.RawSubject; !bytes.Equal(subject, test.want) {
				t.Fatalf("expected template subject %x, got %x", test.want, subject)
			}
			if sender := directoryNameContent(t, message.Header.Sender); !bytes.Equal(sender, test.want) {
				t.Fatalf("expected sender %x, got %x", test.want, sender)
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
