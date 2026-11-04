/*
Copyright 2026 The cmp-issuer Authors.

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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Signature algorithm identifiers the signature digest tests expect.
var (
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

// rsa4096Key is generated once, because a 4096-bit key is the case that selects SHA-512 by default.
var rsa4096Key = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	return key
}()

// rsaIRRequest returns a MAC-protected IR whose workload key is the shared RSA 4096 key.
func rsaIRRequest(t *testing.T, pki testPKI, endpoint string) EnrollmentRequest {
	t.Helper()
	request := irEnrollmentRequest(t, pki, endpoint, false)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "worker.example"},
		DNSNames: []string{"worker.example"},
	}, rsa4096Key)
	if err != nil {
		t.Fatal(err)
	}
	request.CSRDER = csrDER
	request.RequestedPrivateKey = rsa4096Key
	return request
}

// popAlgorithm builds the request message and returns the proof of possession algorithm and the
// protection algorithm the server receives.
func popAlgorithm(t *testing.T, request EnrollmentRequest) (asn1.ObjectIdentifier, asn1.ObjectIdentifier) {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := credentialsFor(request)
	if err != nil {
		t.Fatal(err)
	}
	build := protectedIR
	if request.Operation == OperationKUR {
		build = protectedKUR
	}
	_, encoded, err := build(request, csr, credentials)
	if err != nil {
		t.Fatalf("build %s: %v", request.Operation, err)
	}
	message, err := pkicmp.ParsePKIMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := message.Body.IR()
	if request.Operation == OperationKUR {
		messages, err = message.Body.KUR()
	}
	if err != nil || messages == nil || len(*messages) != 1 {
		t.Fatalf("parse %s body: %v", request.Operation, err)
	}
	certificateRequest := (*messages)[0]
	if err := pkicmp.VerifyPOP(&certificateRequest); err != nil {
		t.Fatalf("verify proof of possession: %v", err)
	}
	if certificateRequest.Popo == nil || certificateRequest.Popo.Signature == nil || message.Header.ProtectionAlg == nil {
		t.Fatal("expected a signature proof of possession and message protection")
	}
	return certificateRequest.Popo.Signature.Algorithm.Algorithm, message.Header.ProtectionAlg.Algorithm
}

// TestSignatureDigestIRProofOfPossession verifies the IR proof of possession follows the key when no
// digest is set and uses the configured digest otherwise.
func TestSignatureDigestIRProofOfPossession(t *testing.T) {
	pki := newTestPKI(t)
	for _, test := range []struct {
		name   string
		digest crypto.Hash
		want   asn1.ObjectIdentifier
	}{
		{name: "RSA 4096 follows the key", want: oidSHA512WithRSA},
		{name: "RSA 4096 with SHA-256", digest: crypto.SHA256, want: oidSHA256WithRSA},
		{name: "RSA 4096 with SHA-384", digest: crypto.SHA384, want: oidSHA384WithRSA},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := rsaIRRequest(t, pki, "https://cmp.example.test")
			request.SignatureDigest = test.digest
			pop, _ := popAlgorithm(t, request)
			if !pop.Equal(test.want) {
				t.Fatalf("expected proof of possession algorithm %s, got %s", test.want, pop)
			}
		})
	}
}

// TestSignatureDigestSignatureProtection verifies a signature-protected IR and a KUR sign both the
// proof of possession and the message protection with the configured digest.
func TestSignatureDigestSignatureProtection(t *testing.T) {
	pki := newTestPKI(t)
	for _, test := range []struct {
		name    string
		request func() EnrollmentRequest
	}{
		{name: "IR with bootstrap certificate", request: func() EnrollmentRequest {
			return irEnrollmentRequest(t, pki, "https://cmp.example.test", true)
		}},
		{name: "KUR", request: func() EnrollmentRequest {
			return kurEnrollmentRequest(t, pki, "https://cmp.example.test", true)
		}},
	} {
		t.Run(test.name+" follows the P-256 key", func(t *testing.T) {
			pop, protection := popAlgorithm(t, test.request())
			if !pop.Equal(oidECDSAWithSHA256) || !protection.Equal(oidECDSAWithSHA256) {
				t.Fatalf("expected ECDSA with SHA-256, got proof of possession %s and protection %s", pop, protection)
			}
		})
		t.Run(test.name+" with SHA-384", func(t *testing.T) {
			request := test.request()
			request.SignatureDigest = crypto.SHA384
			pop, protection := popAlgorithm(t, request)
			if !pop.Equal(oidECDSAWithSHA384) || !protection.Equal(oidECDSAWithSHA384) {
				t.Fatalf("expected ECDSA with SHA-384, got proof of possession %s and protection %s", pop, protection)
			}
		})
	}
}

// TestSignatureDigestEnrollIR verifies a server accepts and issues an IR whose RSA 4096 proof of
// possession is pinned to SHA-256.
func TestSignatureDigestEnrollIR(t *testing.T) {
	pki := newTestPKI(t)
	server, _ := newMockCMPServer(t, pki, testIRPassword, nil, mockOptions{})
	defer server.Close()
	request := rsaIRRequest(t, pki, server.URL)
	request.SignatureDigest = crypto.SHA256
	client := NewClient()
	result, err := client.EnrollIR(context.Background(), request)
	if err == nil {
		result, err = confirmToCompletion(t, client, request, result)
	}
	if err != nil {
		t.Fatalf("EnrollIR returned error: %v", err)
	}
	if len(result.Chain) != 1 || !PublicKeysEqual(result.Chain[0].PublicKey, rsa4096Key.Public()) {
		t.Fatal("issued certificate does not contain the requested RSA key")
	}
}

// TestSignatureDigestValidation verifies an unsupported digest is refused before any network send
// and that keys whose signatures take no digest ignore it.
func TestSignatureDigestValidation(t *testing.T) {
	pki := newTestPKI(t)
	request := irEnrollmentRequest(t, pki, "https://cmp.example.test", false)
	request.SignatureDigest = crypto.SHA1
	err := ValidateIRRequest(request)
	var protocolErr *Error
	if !errors.As(err, &protocolErr) || protocolErr.Failure != "badAlg" {
		t.Fatalf("expected a badAlg error for SHA-1, got %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if digest := signatureDigestFor(edKey, crypto.SHA256); digest != 0 {
		t.Fatalf("expected Ed25519 to ignore the digest, got %v", digest)
	}
	if digest := signatureDigestFor(rsa4096Key, crypto.SHA256); digest != crypto.SHA256 {
		t.Fatalf("expected RSA to use the digest, got %v", digest)
	}
}
