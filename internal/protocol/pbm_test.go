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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// TestPBMAlgorithmsAgainstOpenSSL checks every supported suite on the wire against an independent server.
func TestPBMAlgorithmsAgainstOpenSSL(t *testing.T) {
	for _, owf := range []crypto.Hash{0, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		for _, mac := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			if owf == 0 && mac != crypto.SHA256 || owf != 0 && mac.Size() > owf.Size() {
				continue
			}
			t.Run(fmt.Sprintf("%v/%v", owf, mac), func(t *testing.T) {
				pki := newTestPKI(t)
				request := baseEnrollmentRequest(t, pki, "")
				request.Protection.Password = &PasswordProtection{Reference: []byte(opensslMockReference), Secret: []byte(opensslMockPassword), IterationCount: 1024, OWF: owf, MAC: mac}
				expectedOWF := owf
				if owf == 0 {
					request.Protection.Password.MAC = 0
					expectedOWF = crypto.SHA256
				}
				csr, err := x509.ParseCertificateRequest(request.CSRDER)
				if err != nil {
					t.Fatal(err)
				}
				polls := 0
				if owf == mac {
					polls = 1
				}
				proxy, forwarded := newSingleConnectionProxy(t, startOpenSSLMockServer(t, pki, issueLeaf(t, pki, csr, csr.PublicKey), polls))
				request.EndpointURL = proxy.URL
				client := NewClient()
				result, err := client.EnrollP10CR(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				for count := 0; result.Pending != nil; count++ {
					if count >= 4 {
						t.Fatal("enrollment exceeded the expected poll count")
					}
					pending := result.Pending
					time.Sleep(pending.CheckAfter)
					result, err = client.PollP10CR(context.Background(), PollRequest{Enrollment: request, RecipNonce: pending.RecipNonce, CertReqID: pending.CertReqID, ResponseSigner: pending.ResponseSigner, RequestNonce: pending.RequestNonce})
					if err != nil {
						t.Fatal(err)
					}
				}
				result, err = confirmToCompletion(t, client, request, result)
				if err != nil || !result.ExplicitConfirmation {
					t.Fatalf("PBM confirmation: result=%+v error=%v", result, err)
				}
				count := 0
				for ; forwarded.at(count) != nil; count++ {
					requirePBMSuite(t, forwarded.at(count), expectedOWF, mac)
				}
				if count < 2 || polls > 0 && count < 4 {
					t.Fatalf("expected enrollment and confirmation traffic, got %d messages", count)
				}
			})
		}
	}
}

// requirePBMSuite decodes the transmitted algorithm identifiers without relying on the CMP credential builder.
func requirePBMSuite(t *testing.T, data []byte, owf crypto.Hash, mac crypto.Hash) {
	t.Helper()
	message, err := pkicmp.ParsePKIMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	var parameters struct {
		Salt           []byte
		OWF            pkix.AlgorithmIdentifier
		IterationCount int
		MAC            pkix.AlgorithmIdentifier
	}
	if message.Header.ProtectionAlg == nil || message.Header.ProtectionAlg.Algorithm.String() != "1.2.840.113533.7.66.13" {
		t.Fatal("expected PasswordBasedMac protection")
	}
	if _, err := asn1.Unmarshal(message.Header.ProtectionAlg.Parameters, &parameters); err != nil {
		t.Fatal(err)
	}
	owfOIDs := map[crypto.Hash]string{crypto.SHA256: "2.16.840.1.101.3.4.2.1", crypto.SHA384: "2.16.840.1.101.3.4.2.2", crypto.SHA512: "2.16.840.1.101.3.4.2.3"}
	macOIDs := map[crypto.Hash]string{crypto.SHA256: "1.2.840.113549.2.9", crypto.SHA384: "1.2.840.113549.2.10", crypto.SHA512: "1.2.840.113549.2.11"}
	if parameters.OWF.Algorithm.String() != owfOIDs[owf] || parameters.MAC.Algorithm.String() != macOIDs[mac] || parameters.IterationCount != 1024 {
		t.Fatalf("unexpected PBM parameters: OWF=%s MAC=%s iterations=%d", parameters.OWF.Algorithm, parameters.MAC.Algorithm, parameters.IterationCount)
	}
}

// TestPBMRejectsUnsupportedAlgorithms verifies unsupported suites fail before sending any request.
func TestPBMRejectsUnsupportedAlgorithms(t *testing.T) {
	for _, test := range []struct {
		name string
		owf  crypto.Hash
		mac  crypto.Hash
	}{
		{name: "SHA1 OWF", owf: crypto.SHA1, mac: crypto.SHA256},
		{name: "SHA1 MAC", owf: crypto.SHA256, mac: crypto.SHA1},
		{name: "SHA224", owf: crypto.SHA224, mac: crypto.SHA224},
		{name: "SHA384 expansion", owf: crypto.SHA256, mac: crypto.SHA384},
		{name: "SHA512 expansion", owf: crypto.SHA384, mac: crypto.SHA512},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			password := []byte("test-shared-secret")
			server, state := newMockCMPServer(t, pki, password, nil, mockOptions{})
			defer server.Close()
			request := baseEnrollmentRequest(t, pki, server.URL)
			request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024, OWF: test.owf, MAC: test.mac}
			_, err := NewClient().EnrollP10CR(context.Background(), request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != ErrorKindPermanent || state.count() != 0 {
				t.Fatalf("expected rejection before transmission, got %v and %d messages", err, state.count())
			}
		})
	}
}
