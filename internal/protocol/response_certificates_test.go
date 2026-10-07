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
	"encoding/asn1"
	"errors"
	"testing"
)

// TestConfiguredResponseSigner verifies an omitted non-anchor signer under both response profiles.
func TestConfiguredResponseSigner(t *testing.T) {
	for _, test := range []struct {
		name     string
		password bool
		strict   bool
	}{
		{name: "signature"},
		{name: "RFC9483", strict: true},
		{name: "signed PBM response", password: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			key, certificate := newSubordinateAuthority(t, pki, "CMP Responder")
			request := anchorEnrollmentRequest(t, pki, "")
			request.Recipient = certificate.Subject
			request.CMPResponseCertificates = []*x509.Certificate{certificate}
			var password []byte
			if test.password {
				password = []byte("test-shared-secret")
				request.Protection = Protection{Password: &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}}
				request.AllowSignedMACResponse = true
			}
			if test.strict {
				request.ResponseCertReqID = pinCertReqID(ResponseCertReqIDStandard)
				request.RequireKUPCAPubsAbsent = true
			}
			server, state := newMockCMPServer(t, pki, password, request.CMPTrust, mockOptions{CertReqID: ResponseCertReqIDStandard, OmitExtraCerts: true, ForceSignature: true, ResponseSigner: &SignatureProtection{PrivateKey: key, Certificate: certificate}})
			defer server.Close()
			request.EndpointURL = server.URL
			result, err := NewClient().EnrollP10CR(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.PendingConfirmation == nil || !certificate.Equal(result.PendingConfirmation.ResponseSigner) {
				t.Fatal("expected the configured non-anchor signer to be retained")
			}
			request.CMPResponseCertificates = nil
			result, err = confirmToCompletion(t, NewClient(), request, result)
			if err != nil || !result.ExplicitConfirmation || state.count() != 2 {
				t.Fatalf("confirm using the retained signer: result=%+v error=%v", result, err)
			}
		})
	}
}

// TestConfiguredResponseCertificatesBuildIssuedChain keeps configured intermediates separate from trust anchors.
func TestConfiguredResponseCertificatesBuildIssuedChain(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "trusted issuer", false: "untrusted issuer"}[trusted], func(t *testing.T) {
			pki := newTestPKI(t)
			key, certificate := newSubordinateAuthority(t, pki, "CMP Responder")
			request := anchorEnrollmentRequest(t, pki, "")
			request.Recipient = certificate.Subject
			request.CMPResponseCertificates = []*x509.Certificate{certificate}
			issuingPKI := pki
			issuingPKI.CAKey, issuingPKI.CACertificate = key, certificate
			if !trusted {
				untrustedPKI := newTestPKI(t)
				issuingPKI.CAKey, issuingPKI.CACertificate = newSubordinateAuthority(t, untrustedPKI, "Untrusted Issuer")
				request.CMPResponseCertificates = append(request.CMPResponseCertificates, issuingPKI.CACertificate, untrustedPKI.CACertificate)
			}
			server, _ := newMockCMPServer(t, issuingPKI, nil, request.CMPTrust, mockOptions{CertReqID: ResponseCertReqIDStandard, OmitExtraCerts: true, ResponseSigner: &SignatureProtection{PrivateKey: key, Certificate: certificate}})
			defer server.Close()
			request.EndpointURL = server.URL
			result, err := enrollAndConfirm(t, request)
			if trusted {
				if err != nil || !result.ExplicitConfirmation || len(result.Chain) != 2 {
					t.Fatalf("expected the configured intermediate in the issued chain, got result=%+v error=%v", result, err)
				}
				return
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Operation != "validate issued chain" {
				t.Fatalf("expected an untrusted issued chain to be rejected, got %v", err)
			}
		})
	}
}

// TestConfiguredResponseSignerKUR verifies omitted non-anchor signers with both workload key policies.
func TestConfiguredResponseSignerKUR(t *testing.T) {
	for _, test := range keyRotationCases {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			key, certificate := newSubordinateAuthority(t, pki, "CMP Responder")
			request := kurEnrollmentRequest(t, pki, "", test.rotateKey)
			request.Recipient = certificate.Subject
			request.CMPResponseCertificates = []*x509.Certificate{certificate}
			server, _ := newMockCMPServer(t, pki, nil, request.CMPTrust, mockOptions{CertReqID: ResponseCertReqIDLegacyZero, OmitExtraCerts: true, ResponseSigner: &SignatureProtection{PrivateKey: key, Certificate: certificate}})
			defer server.Close()
			request.EndpointURL = server.URL
			result, err := NewClient().EnrollKUR(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := confirmToCompletion(t, NewClient(), request, result); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestConfiguredResponseSignerRejectsInvalidResponses preserves trust and identity checks for out-of-band certificates.
func TestConfiguredResponseSignerRejectsInvalidResponses(t *testing.T) {
	for _, test := range []struct {
		name           string
		omitCandidate  bool
		untrusted      bool
		wrongRecipient bool
		options        mockOptions
		failure        string
	}{
		{name: "missing candidate", omitCandidate: true, failure: testBadMessageCheck},
		{name: "untrusted candidate", untrusted: true, failure: testBadMessageCheck},
		{name: "wrong authority", wrongRecipient: true, failure: testWrongAuthority},
		{name: "sender mismatch", options: mockOptions{WrongSignerSubject: true}, failure: testBadMessageCheck},
		{name: "tampered protection", options: mockOptions{InvalidProtection: true}, failure: testBadMessageCheck},
		{name: "tampered confirmation", options: mockOptions{InvalidPKIConf: true}, failure: testBadMessageCheck},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			signingPKI := pki
			if test.untrusted {
				signingPKI = newTestPKI(t)
			}
			key, certificate := newSubordinateAuthority(t, signingPKI, "CMP Responder")
			request := anchorEnrollmentRequest(t, pki, "")
			request.Recipient = certificate.Subject
			if test.wrongRecipient {
				request.Recipient = pki.CACertificate.Subject
			}
			if !test.omitCandidate {
				request.CMPResponseCertificates = []*x509.Certificate{certificate}
			}
			test.options.CertReqID = ResponseCertReqIDStandard
			test.options.OmitExtraCerts = true
			test.options.ResponseSigner = &SignatureProtection{PrivateKey: key, Certificate: certificate}
			server, _ := newMockCMPServer(t, pki, nil, request.CMPTrust, test.options)
			defer server.Close()
			request.EndpointURL = server.URL
			_, err := enrollAndConfirm(t, request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != test.failure {
				t.Fatalf("expected %s, got %v", test.failure, err)
			}
		})
	}
}

// TestConfiguredResponseSignerAgainstOpenSSL verifies an omitted non-anchor signer with an independent responder.
func TestConfiguredResponseSignerAgainstOpenSSL(t *testing.T) {
	pki := newTestPKI(t)
	key, certificate := newSubordinateAuthority(t, pki, "CMP Responder")
	request := anchorEnrollmentRequest(t, pki, "")
	request.Recipient = certificate.Subject
	request.CMPResponseCertificates = []*x509.Certificate{certificate}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		t.Fatal(err)
	}
	issued := issueLeaf(t, pki, csr, csr.PublicKey)
	proxy, _ := newSingleConnectionResponseProxy(t, startOpenSSLSignatureMockServer(t, pki, pki.BootstrapCertificate, issued, &SignatureProtection{PrivateKey: key, Certificate: certificate}, false), omitResponseCertificates)
	request.EndpointURL = proxy.URL
	result, err := enrollAndConfirm(t, request)
	if err != nil || !result.ExplicitConfirmation || result.ExtraCertificateCount != 0 {
		t.Fatalf("OpenSSL response signer verification: result=%+v error=%v", result, err)
	}
}

// omitResponseCertificates removes unprotected extraCerts while preserving the signed DER fields byte for byte.
func omitResponseCertificates(data []byte) ([]byte, error) {
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	filtered := make([]asn1.RawValue, 0, len(fields))
	for _, field := range fields {
		if field.Class != asn1.ClassContextSpecific || field.Tag != 1 {
			filtered = append(filtered, field)
		}
	}
	return asn1.Marshal(filtered)
}
