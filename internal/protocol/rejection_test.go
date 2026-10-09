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
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// macEnrollmentRequest creates a PasswordBasedMac P10CR request for the mock CMP server.
func macEnrollmentRequest(t *testing.T, pki testPKI, endpoint string, password []byte) EnrollmentRequest {
	t.Helper()
	request := baseEnrollmentRequest(t, pki, endpoint)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	return request
}

// requireRejection fails unless the mock server received exactly the request and a rejecting certConf.
func requireRejection(t *testing.T, state *mockState, request pkicmp.BodyType) {
	t.Helper()
	if observed := state.observedBodies(); !slices.Equal(observed, []pkicmp.BodyType{request, pkicmp.BodyTypeCertConf}) {
		t.Fatalf("expected %s followed by certConf, got %v", request, observed)
	}
	status, _, _ := state.confirmationDetail()
	if status.StatusInfo == nil || status.StatusInfo.Status != pkicmp.StatusRejection {
		t.Fatalf("expected certConf to reject the certificate, got %+v", status.StatusInfo)
	}
}

// TestRefusedCertificateIsRejectedInCertConf verifies that every refusal of an issued certificate is
// reported to the server, which expects certConf, while the refusal itself is still returned.
func TestRefusedCertificateIsRejectedInCertConf(t *testing.T) {
	for _, test := range []struct {
		name      string
		options   mockOptions
		otherRoot bool
		kind      ErrorKind
		failure   string
	}{
		{name: "public key mismatch", options: mockOptions{CertReqID: ResponseCertReqIDStandard, WrongPublicKey: true}, kind: ErrorKindSecurity, failure: testFailurePublicKeyMismatch},
		{name: "untrusted chain", options: mockOptions{CertReqID: ResponseCertReqIDStandard}, otherRoot: true, kind: ErrorKindSecurity, failure: "signerNotTrusted"},
		{name: "granted modifications", options: mockOptions{CertReqID: ResponseCertReqIDStandard, GrantedWithMods: true}, kind: ErrorKindPermanent, failure: "grantedWithMods"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			password := []byte("test-shared-secret")
			server, state := newMockCMPServer(t, pki, password, nil, test.options)
			defer server.Close()
			request := macEnrollmentRequest(t, pki, server.URL, password)
			if test.otherRoot {
				request.CMPTrust = x509.NewCertPool()
				request.CMPTrust.AddCert(newTestPKI(t).CACertificate)
			}
			_, err := NewClient().EnrollP10CR(context.Background(), request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != test.kind || typed.Failure != test.failure {
				t.Fatalf("expected %s %s, got %v", test.kind, test.failure, err)
			}
			if strings.Contains(err.Error(), "rejection not confirmed") {
				t.Fatalf("expected the server to confirm the rejection, got %v", err)
			}
			requireRejection(t, state, pkicmp.BodyTypeP10CR)
		})
	}
}

// TestRefusedKURCertificateIsRejectedInCertConf verifies that a KUP certifying another key is rejected in certConf.
func TestRefusedKURCertificateIsRejectedInCertConf(t *testing.T) {
	pki := newTestPKI(t)
	bootstrapRoots := x509.NewCertPool()
	bootstrapRoots.AddCert(pki.CACertificate)
	server, state := newMockCMPServer(t, pki, nil, bootstrapRoots, mockOptions{CertReqID: ResponseCertReqIDLegacyZero, WrongPublicKey: true})
	defer server.Close()
	_, err := NewClient().EnrollKUR(context.Background(), kurEnrollmentRequest(t, pki, server.URL, true))
	var typed *Error
	if !errors.As(err, &typed) || typed.Failure != testFailurePublicKeyMismatch {
		t.Fatalf("expected publicKeyMismatch, got %v", err)
	}
	requireRejection(t, state, pkicmp.BodyTypeKUR)
}

// TestImplicitlyConfirmedRefusalSendsNoCertConf verifies that a certificate the server confirmed
// implicitly is refused without a certConf, which the server no longer expects.
func TestImplicitlyConfirmedRefusalSendsNoCertConf(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: ResponseCertReqIDStandard, WrongPublicKey: true, GrantImplicitConfirm: true})
	defer server.Close()
	request := macEnrollmentRequest(t, pki, server.URL, password)
	request.ImplicitConfirm = true
	_, err := NewClient().EnrollP10CR(context.Background(), request)
	var typed *Error
	if !errors.As(err, &typed) || typed.Failure != testFailurePublicKeyMismatch {
		t.Fatalf("expected publicKeyMismatch, got %v", err)
	}
	if observed := state.observedBodies(); !slices.Equal(observed, []pkicmp.BodyType{pkicmp.BodyTypeP10CR}) {
		t.Fatalf("expected no certConf after implicit confirmation, got %v", observed)
	}
}

// TestUndeliveredRejectionKeepsTheRefusal verifies that a rejection the server does not confirm leaves
// the refusal and its classification unchanged and says so in the error.
func TestUndeliveredRejectionKeepsTheRefusal(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: ResponseCertReqIDStandard, WrongPublicKey: true, FailCertConf: true})
	defer server.Close()
	_, err := NewClient().EnrollP10CR(context.Background(), macEnrollmentRequest(t, pki, server.URL, password))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != testFailurePublicKeyMismatch {
		t.Fatalf("expected the publicKeyMismatch refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "rejection not confirmed by the server") {
		t.Fatalf("expected the error to report the unconfirmed rejection, got %v", err)
	}
	requireRejection(t, state, pkicmp.BodyTypeP10CR)
}
