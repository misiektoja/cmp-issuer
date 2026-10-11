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
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"github.com/misiektoja/go-pki-cmp/server"
)

// immediateCA issues every request at once from the template the CMP server builds.
type immediateCA struct {
	// pki supplies the signing key and issuer certificate.
	pki testPKI
}

// IssueCertificate signs the template with the test CA.
func (c immediateCA) IssueCertificate(_ context.Context, _ server.RequestType, template *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	certificate, err := issueFromTemplate(c.pki, template)
	if err != nil {
		return nil, err
	}
	return &server.Response{Certificate: certificate}, nil
}

// TestEnrollKURAgainstLightweightCMPServer verifies a go-pki-cmp server enforcing the RFC 9483 profile
// accepts the KUR and issues the certificate under the exact subject it replaces.
func TestEnrollKURAgainstLightweightCMPServer(t *testing.T) {
	for _, test := range kurSubjectCases(t) {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			var current *x509.Certificate
			lookup := server.CertificateLookupFunc(func(_ pkix.Name, _ pkix.Name, _ []byte) (*x509.Certificate, error) { return current, nil })
			handler := server.NewCAServer(
				immediateCA{pki: pki},
				server.LightweightPolicy(),
				server.WithSigner(pki.CAKey, pki.CACertificate),
				server.WithSender(pki.CACertificate.Subject),
				server.WithCertificateLookup(lookup),
				server.WithRawSubject(),
			)
			endpoint := httptest.NewServer(handler)
			defer endpoint.Close()
			request := kurRequestForSubject(t, pki, endpoint.URL, test)
			current = request.Protection.Signature.Certificate
			client := NewClient()
			result, err := client.EnrollKUR(context.Background(), request)
			if err == nil {
				result, err = confirmToCompletion(t, client, request, result)
			}
			if err != nil {
				t.Fatalf("EnrollKUR returned error: %v", err)
			}
			if len(result.Chain) == 0 || !bytes.Equal(result.Chain[0].RawSubject, test.want) {
				t.Fatalf("expected the issued certificate to carry subject %x", test.want)
			}
		})
	}
}
