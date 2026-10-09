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
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// oidSHA512 identifies SHA-512, the hashAlg a certConf names for an ML-DSA-signed certificate.
var oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

// mldsaParameterSets lists every ML-DSA parameter set crypto/mldsa implements.
var mldsaParameterSets = []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}

// newMLDSAKey generates an ML-DSA private key for one parameter set.
func newMLDSAKey(t *testing.T, parameters mldsa.Parameters) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(parameters)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newMLDSAPKI creates an ML-DSA-65 root with an ML-DSA-44 bootstrap credential.
func newMLDSAPKI(t *testing.T) testPKI {
	t.Helper()
	return newTestPKIWithKeys(t, newMLDSAKey(t, mldsa.MLDSA65()), newMLDSAKey(t, mldsa.MLDSA44()))
}

// TestEnrollP10CRWithMLDSAKeys verifies that an ML-DSA CSR of every parameter set enrolls and confirms.
func TestEnrollP10CRWithMLDSAKeys(t *testing.T) {
	for _, parameters := range mldsaParameterSets {
		t.Run(parameters.String(), func(t *testing.T) {
			pki := newTestPKI(t)
			password := []byte("test-shared-secret")
			server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: ResponseCertReqIDStandard})
			defer server.Close()
			key := newMLDSAKey(t, parameters)
			request := baseEnrollmentRequest(t, pki, server.URL)
			request.CSRDER = createCSRWithKey(t, "cmp-issuer-mldsa-test", key)
			request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
			result, err := enrollAndConfirm(t, request)
			if err != nil {
				t.Fatalf("enrollment returned error: %v", err)
			}
			if !result.ExplicitConfirmation || len(result.Chain) != 1 || !PublicKeysEqual(result.Chain[0].PublicKey, key.Public()) {
				t.Fatal("expected a confirmed certificate carrying the ML-DSA key")
			}
			// The issuing CA signs with ECDSA, whose signature algorithm implies the certConf hash.
			status, pvno, observed := state.confirmationDetail()
			if !observed || status.HashAlg != nil || pvno != pkicmp.PVNO2 {
				t.Fatalf("expected a CMPv2 certConf without hashAlg, got version %d and hashAlg %v", pvno, status.HashAlg)
			}
		})
	}
}

// TestEnrollP10CRFromMLDSAAuthority verifies an ML-DSA CA, ML-DSA response signatures, an ML-DSA
// protection credential and the CMPv3 certConf an ML-DSA-signed certificate requires.
func TestEnrollP10CRFromMLDSAAuthority(t *testing.T) {
	for _, test := range []struct {
		name     string
		password []byte
	}{
		{name: "signature protection"},
		{name: "PasswordBasedMac protection", password: []byte("test-shared-secret")},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newMLDSAPKI(t)
			bootstrapRoots := x509.NewCertPool()
			bootstrapRoots.AddCert(pki.CACertificate)
			server, state := newMockCMPServer(t, pki, test.password, bootstrapRoots, mockOptions{CertReqID: ResponseCertReqIDStandard})
			defer server.Close()
			key := newMLDSAKey(t, mldsa.MLDSA65())
			request := baseEnrollmentRequest(t, pki, server.URL)
			request.CSRDER = createCSRWithKey(t, "cmp-issuer-mldsa-test", key)
			if test.password != nil {
				request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: test.password, IterationCount: 1024}
			} else {
				request.Protection.Signature = &SignatureProtection{PrivateKey: pki.BootstrapKey, Certificate: pki.BootstrapCertificate, Chain: []*x509.Certificate{pki.CACertificate}}
			}
			result, err := enrollAndConfirm(t, request)
			if err != nil {
				t.Fatalf("enrollment returned error: %v", err)
			}
			if !result.ExplicitConfirmation || len(result.Chain) != 1 || result.Chain[0].SignatureAlgorithm != x509.MLDSA65 {
				t.Fatal("expected a confirmed certificate signed by the ML-DSA CA")
			}
			status, pvno, observed := state.confirmationDetail()
			if !observed || pvno != pkicmp.PVNO3 || status.HashAlg == nil || !status.HashAlg.Algorithm.Equal(oidSHA512) {
				t.Fatalf("expected a CMPv3 certConf naming SHA-512, got version %d and hashAlg %v", pvno, status.HashAlg)
			}
			want := sha512.Sum512(result.Chain[0].Raw)
			if string(status.CertHash) != string(want[:]) {
				t.Fatal("expected certHash to be the SHA-512 digest of the issued certificate")
			}
		})
	}
}

// TestConfirmationAcceptsCMPv2AnswerToCMPv3 verifies that a server answering a CMPv3 certConf in CMPv2 is accepted.
func TestConfirmationAcceptsCMPv2AnswerToCMPv3(t *testing.T) {
	pki := newMLDSAPKI(t)
	password := []byte("test-shared-secret")
	server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: ResponseCertReqIDStandard, ResponsePVNO: pkicmp.PVNO2})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	result, err := enrollAndConfirm(t, request)
	if err != nil {
		t.Fatalf("enrollment returned error: %v", err)
	}
	if _, pvno, _ := state.confirmationDetail(); !result.ExplicitConfirmation || pvno != pkicmp.PVNO3 {
		t.Fatalf("expected a CMPv3 certConf confirmed by a CMPv2 pkiConf, got certConf version %d", pvno)
	}
}

// TestEnrollP10CRRejectsUnrequestedCMPv3Response verifies that a CMPv3 answer to a CMPv2 request is refused.
func TestEnrollP10CRRejectsUnrequestedCMPv3Response(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, _ := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: ResponseCertReqIDStandard, ResponsePVNO: pkicmp.PVNO3})
	defer server.Close()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	_, err := NewClient().EnrollP10CR(context.Background(), request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindPermanent || typed.Failure != "unsupportedVersion" {
		t.Fatalf("expected unsupportedVersion, got %v", err)
	}
}

// TestConfirmationMessageVersion verifies that certConf and the pollReq resuming it use CMPv3 only
// for a certificate whose signature algorithm implies no hash.
func TestConfirmationMessageVersion(t *testing.T) {
	for _, test := range []struct {
		name string
		pki  func(*testing.T) testPKI
		want int
	}{
		{name: "ECDSA CA", pki: newTestPKI, want: pkicmp.PVNO2},
		{name: "ML-DSA CA", pki: newMLDSAPKI, want: pkicmp.PVNO3},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := test.pki(t)
			request := baseEnrollmentRequest(t, pki, "https://cmp.example.test")
			request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: []byte("test-shared-secret"), IterationCount: 1024}
			csr, err := x509.ParseCertificateRequest(request.CSRDER)
			if err != nil {
				t.Fatal(err)
			}
			certificate := issueLeaf(t, pki, csr, csr.PublicKey)
			credentials, err := credentialsFor(request.Protection)
			if err != nil {
				t.Fatal(err)
			}
			for name, requestNonce := range map[string][]byte{"certConf": nil, "pollReq": freshNonce(t)} {
				confirm := ConfirmRequest{Enrollment: request, Certificate: certificate, CertReqID: ResponseCertReqIDStandard, RecipNonce: freshNonce(t), RequestNonce: requestNonce}
				message, _, err := confirmationMessage(request, confirm, nil)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if err := credentials.Protect(message); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if message.Header.PVNO != test.want {
					t.Fatalf("%s: expected protocol version %d, got %d", name, test.want, message.Header.PVNO)
				}
			}
		})
	}
}

// kurRequestWithKeys creates a KUR request that renews a certificate for currentKey with requestedKey.
func kurRequestWithKeys(t *testing.T, pki testPKI, endpoint string, currentKey crypto.Signer, requestedKey crypto.Signer) EnrollmentRequest {
	t.Helper()
	currentCSR, err := x509.ParseCertificateRequest(createCSRWithKey(t, "cmp-issuer-kur-test", currentKey))
	if err != nil {
		t.Fatal(err)
	}
	currentCertificate := issueLeaf(t, pki, currentCSR, currentKey.Public())
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

// TestEnrollKURWithMLDSAKeys verifies new-key and same-key ML-DSA updates under an ML-DSA CA. The
// current ML-DSA key protects the request and the requested key signs the CRMF proof of possession.
func TestEnrollKURWithMLDSAKeys(t *testing.T) {
	for _, test := range keyRotationCases {
		t.Run(test.name, func(t *testing.T) {
			pki := newMLDSAPKI(t)
			bootstrapRoots := x509.NewCertPool()
			bootstrapRoots.AddCert(pki.CACertificate)
			server, state := newMockCMPServer(t, pki, nil, bootstrapRoots, mockOptions{CertReqID: ResponseCertReqIDLegacyZero})
			defer server.Close()
			currentKey := newMLDSAKey(t, mldsa.MLDSA65())
			requestedKey := currentKey
			if test.rotateKey {
				requestedKey = newMLDSAKey(t, mldsa.MLDSA65())
			}
			request := kurRequestWithKeys(t, pki, server.URL, currentKey, requestedKey)
			client := NewClient()
			result, err := client.EnrollKUR(context.Background(), request)
			if err == nil {
				result, err = confirmToCompletion(t, client, request, result)
			}
			if err != nil {
				t.Fatalf("EnrollKUR returned error: %v", err)
			}
			if len(result.Chain) != 1 || !PublicKeysEqual(result.Chain[0].PublicKey, requestedKey.Public()) {
				t.Fatal("issued KUR certificate does not contain the requested ML-DSA key")
			}
			if _, pvno, observed := state.confirmationDetail(); !observed || pvno != pkicmp.PVNO3 {
				t.Fatalf("expected a CMPv3 certConf for the ML-DSA-signed certificate, got version %d", pvno)
			}
		})
	}
}
