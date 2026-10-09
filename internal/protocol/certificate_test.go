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
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// certificateWithKeyUsage signs a copy with the requested keyUsage extension.
func certificateWithKeyUsage(t *testing.T, certificate *x509.Certificate, parent *x509.Certificate, signer crypto.Signer, usage x509.KeyUsage, empty bool) *x509.Certificate {
	t.Helper()
	template := *certificate
	template.KeyUsage = usage
	template.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	if empty {
		template.ExtraExtensions = []pkix.Extension{{Id: oidKeyUsage, Critical: true, Value: []byte{3, 1, 0}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, parent, certificate.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// TestValidateMLDSAKeyUsage checks all parameter sets and the optional extension's allowed bits.
func TestValidateMLDSAKeyUsage(t *testing.T) {
	pki := newTestPKI(t)
	for _, parameters := range mldsaParameterSets {
		t.Run(parameters.String(), func(t *testing.T) {
			key := newMLDSAKey(t, parameters)
			csr, err := x509.ParseCertificateRequest(createCSRWithKey(t, "key-usage-test", key))
			if err != nil {
				t.Fatal(err)
			}
			leaf := issueLeaf(t, pki, csr, key.Public())
			for _, test := range []struct {
				name      string
				usage     x509.KeyUsage
				empty     bool
				wantError bool
			}{
				{name: "absent extension"},
				{name: "empty extension", empty: true, wantError: true},
				{name: "digital signature", usage: x509.KeyUsageDigitalSignature},
				{name: "content commitment", usage: x509.KeyUsageContentCommitment},
				{name: "certificate signing", usage: x509.KeyUsageCertSign},
				{name: "CRL signing", usage: x509.KeyUsageCRLSign},
				{name: "combined signature usages", usage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
				{name: "key encipherment", usage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, wantError: true},
				{name: "data encipherment", usage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment, wantError: true},
				{name: "key agreement", usage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, wantError: true},
				{name: "encipher only", usage: x509.KeyUsageEncipherOnly, wantError: true},
				{name: "decipher only", usage: x509.KeyUsageDecipherOnly, wantError: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					certificate := certificateWithKeyUsage(t, leaf, pki.CACertificate, pki.CAKey, test.usage, test.empty)
					if err := ValidateMLDSAKeyUsage(certificate); (err != nil) != test.wantError {
						t.Fatalf("ValidateMLDSAKeyUsage returned %v, want error %v", err, test.wantError)
					}
				})
			}
		})
	}
	if err := ValidateMLDSAKeyUsage(nil); err == nil {
		t.Fatal("expected a missing certificate to be rejected")
	}
}

// TestClassicalKeyUsageUnderMLDSACA applies the restriction to the subject key rather than its issuer.
func TestClassicalKeyUsageUnderMLDSACA(t *testing.T) {
	pki := newMLDSAPKI(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(createCSRWithKey(t, "classical-key", key))
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, pki, csr, key.Public())
	leaf = certificateWithKeyUsage(t, leaf, pki.CACertificate, pki.CAKey, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, false)
	roots := x509.NewCertPool()
	roots.AddCert(pki.CACertificate)
	if _, err := validateAndOrderChain(leaf, nil, roots); err != nil {
		t.Fatalf("RSA certificate signed by ML-DSA CA was rejected: %v", err)
	}
}

// TestMLDSAChainKeyUsage checks trust anchors and selects a compliant alternative chain.
func TestMLDSAChainKeyUsage(t *testing.T) {
	pki := newMLDSAPKI(t)
	csrDER, key := createCSR(t, "chain-key-usage")
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, pki, csr, key.Public())
	invalidRoot := certificateWithKeyUsage(t, pki.CACertificate, pki.CACertificate, pki.CAKey, x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment, false)
	roots := x509.NewCertPool()
	roots.AddCert(invalidRoot)
	if _, err := validateAndOrderChain(leaf, nil, roots); err == nil {
		t.Fatal("expected an ML-DSA trust anchor with forbidden usages to be rejected")
	}
	roots.AddCert(pki.CACertificate)
	chain, err := verifyCertificateChain(leaf, roots, x509.NewCertPool())
	if err != nil {
		t.Fatalf("expected a compliant alternative chain: %v", err)
	}
	if !bytes.Equal(chain[len(chain)-1].Raw, pki.CACertificate.Raw) {
		t.Fatal("selected a chain containing the non-compliant trust anchor")
	}
}

// TestMLDSARefusedKeyUsage checks rejecting certConf and implicit-confirmation refusal for both operations.
func TestMLDSARefusedKeyUsage(t *testing.T) {
	for _, operation := range []string{OperationP10CR, OperationKUR} {
		t.Run(operation, func(t *testing.T) {
			for _, implicit := range []bool{false, true} {
				name := "explicit confirmation"
				if implicit {
					name = "implicit confirmation"
				}
				t.Run(name, func(t *testing.T) {
					pki := newTestPKI(t)
					usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
					options := mockOptions{CertReqID: ResponseCertReqIDLegacyZero, IssuedKeyUsage: &usage, GrantImplicitConfirm: implicit}
					key := newMLDSAKey(t, mldsa.MLDSA65())
					var request EnrollmentRequest
					var serverState *mockState
					if operation == OperationP10CR {
						password := []byte("test-shared-secret")
						server, state := newMockCMPServer(t, pki, password, nil, options)
						defer server.Close()
						serverState = state
						request = macEnrollmentRequest(t, pki, server.URL, password)
						request.CSRDER = createCSRWithKey(t, "key-usage-test", key)
					} else {
						roots := x509.NewCertPool()
						roots.AddCert(pki.CACertificate)
						server, state := newMockCMPServer(t, pki, nil, roots, options)
						defer server.Close()
						serverState = state
						request = kurRequestWithKeys(t, pki, server.URL, key, key)
					}
					request.ImplicitConfirm = implicit
					var result EnrollmentResult
					var err error
					bodyType := pkicmp.BodyTypeP10CR
					if operation == OperationKUR {
						bodyType = pkicmp.BodyTypeKUR
						result, err = NewClient().EnrollKUR(context.Background(), request)
					} else {
						result, err = NewClient().EnrollP10CR(context.Background(), request)
					}
					var typed *Error
					if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || len(result.Chain) != 0 || result.PendingConfirmation != nil {
						t.Fatalf("expected refused certificate without a returned chain, got %+v and %v", result, err)
					}
					if implicit {
						if bodies := serverState.observedBodies(); len(bodies) != 1 || bodies[0] != bodyType {
							t.Fatalf("unexpected implicit-confirmation traffic: %v", bodies)
						}
					} else {
						requireRejection(t, serverState, bodyType)
					}
				})
			}
		})
	}
}

// TestMLDSASignatureCredentialKeyUsage rejects a matching key pair with forbidden certificate usages.
func TestMLDSASignatureCredentialKeyUsage(t *testing.T) {
	pki := newMLDSAPKI(t)
	certificate := certificateWithKeyUsage(t, pki.BootstrapCertificate, pki.CACertificate, pki.CAKey, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement, false)
	if err := ValidateSignerCertificate(pki.BootstrapKey, certificate); err == nil {
		t.Fatal("expected the non-compliant ML-DSA signature credential to be rejected")
	}
}

// TestMLDSAConfirmationKeyUsage prevents positive confirmation of a non-compliant stored certificate.
func TestMLDSAConfirmationKeyUsage(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	server, state := newMockCMPServer(t, pki, password, nil, mockOptions{})
	defer server.Close()
	request := macEnrollmentRequest(t, pki, server.URL, password)
	request.TransactionID = []byte("key-usage-confirmation")
	key := newMLDSAKey(t, mldsa.MLDSA65())
	csr, err := x509.ParseCertificateRequest(createCSRWithKey(t, "key-usage-test", key))
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, pki, csr, key.Public())
	leaf = certificateWithKeyUsage(t, leaf, pki.CACertificate, pki.CAKey, x509.KeyUsageKeyEncipherment, false)
	_, err = NewClient().ConfirmP10CR(context.Background(), ConfirmRequest{Enrollment: request, Certificate: leaf})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorKindPermanent || typed.Failure != pkicmp.FailBadCertTemplate.String() {
		t.Fatalf("expected invalid certificate rejection, got %v", err)
	}
	if bodies := state.observedBodies(); len(bodies) != 0 {
		t.Fatalf("sent confirmation for a non-compliant certificate: %v", bodies)
	}
}

// TestMLDSAResponseSignerKeyUsage rejects both supplied and retained non-compliant signers.
func TestMLDSAResponseSignerKeyUsage(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "response certificates"
		if retained {
			name = "retained signer"
		}
		t.Run(name, func(t *testing.T) {
			pki := newMLDSAPKI(t)
			invalid := certificateWithKeyUsage(t, pki.CACertificate, pki.CACertificate, pki.CAKey, x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, false)
			password := []byte("test-shared-secret")
			server, state := newMockCMPServer(t, pki, password, nil, mockOptions{
				ForceSignature: true,
				ResponseSigner: &SignatureProtection{PrivateKey: pki.CAKey, Certificate: invalid},
				OmitExtraCerts: retained,
			})
			defer server.Close()
			request := macEnrollmentRequest(t, pki, server.URL, password)
			request.AllowSignedMACResponse = true
			var err error
			if retained {
				csr, parseErr := x509.ParseCertificateRequest(request.CSRDER)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				leaf := issueLeaf(t, pki, csr, csr.PublicKey)
				_, err = NewClient().ConfirmP10CR(context.Background(), ConfirmRequest{Enrollment: request, Certificate: leaf, ResponseSigner: invalid})
			} else {
				_, err = NewClient().EnrollP10CR(context.Background(), request)
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != ErrorKindSecurity || typed.Failure != testBadMessageCheck {
				t.Fatalf("expected response signer rejection, got %v", err)
			}
			if state.count() != 1 {
				t.Fatalf("expected one failed exchange, got %d", state.count())
			}
		})
	}
}

// TestMLDSAIntermediateKeyUsage rejects forbidden usages in an issuing intermediate.
func TestMLDSAIntermediateKeyUsage(t *testing.T) {
	root := newTestPKI(t)
	pki := newMLDSAPKI(t)
	intermediate := certificateWithKeyUsage(t, pki.CACertificate, root.CACertificate, root.CAKey, x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment, false)
	csrDER, key := createCSR(t, "intermediate-key-usage")
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, pki, csr, key.Public())
	roots := x509.NewCertPool()
	roots.AddCert(root.CACertificate)
	if _, err := validateAndOrderChain(leaf, []*x509.Certificate{intermediate}, roots); err == nil {
		t.Fatal("expected a non-compliant ML-DSA intermediate to be rejected")
	}
	intermediate = certificateWithKeyUsage(t, pki.CACertificate, root.CACertificate, root.CAKey, x509.KeyUsageCertSign, false)
	if _, err := validateAndOrderChain(leaf, []*x509.Certificate{intermediate}, roots); err != nil {
		t.Fatalf("expected a compliant ML-DSA intermediate to be accepted: %v", err)
	}
}
