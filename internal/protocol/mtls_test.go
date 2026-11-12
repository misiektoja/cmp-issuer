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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

const testTLSClientCommonName = "cmp-issuer TLS client"

// newTLSClientCertificate issues a TLS client certificate under an intermediate of pki and returns
// it with the intermediate, as a Secret with tls.crt and tls.key provides it.
func newTLSClientCertificate(t *testing.T, pki testPKI) *tls.Certificate {
	t.Helper()
	intermediateKey, intermediate := newSubordinateAuthority(t, pki, "TLS Client Intermediate")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: testTLSClientCommonName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, intermediate, key.Public(), intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER, intermediate.Raw}, PrivateKey: key, Leaf: leaf}
}

// mTLSEnrollmentRequest returns a PasswordBasedMac P10CR request that trusts the server certificate.
func mTLSEnrollmentRequest(t *testing.T, pki testPKI, server *httptest.Server, password []byte) EnrollmentRequest {
	t.Helper()
	request := baseEnrollmentRequest(t, pki, server.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	request.TLSRoots = x509.NewCertPool()
	request.TLSRoots.AddCert(server.Certificate())
	return request
}

// TestEnrollP10CRPresentsTLSClientCertificate verifies every request of a transaction presents the
// configured client certificate and its intermediate to a server that requires one.
func TestEnrollP10CRPresentsTLSClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	clientPKI := newTestPKI(t)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientPKI.CACertificate)
	password := []byte("test-shared-secret")
	server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: -1, TLSClientCAs: clientCAs})
	defer server.Close()
	request := mTLSEnrollmentRequest(t, pki, server, password)
	request.TLSClientCertificate = newTLSClientCertificate(t, clientPKI)
	if _, err := enrollAndConfirm(t, request); err != nil {
		t.Fatalf("enroll over mTLS: %v", err)
	}
	if presented := state.receivedClientCertificates(); !slices.Equal(presented, []string{testTLSClientCommonName, testTLSClientCommonName}) {
		t.Fatalf("expected the client certificate on the P10CR and certConf, got %v", presented)
	}
}

// TestEnrollP10CRFailsWhenTheServerRefusesTheTLSClient verifies a missing or untrusted client
// certificate fails the exchange as a retryable transport error before any CMP message is read.
func TestEnrollP10CRFailsWhenTheServerRefusesTheTLSClient(t *testing.T) {
	pki := newTestPKI(t)
	clientPKI := newTestPKI(t)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientPKI.CACertificate)
	password := []byte("test-shared-secret")
	for _, test := range []struct {
		name        string
		certificate *tls.Certificate
	}{
		{name: "no client certificate"},
		{name: "untrusted client certificate", certificate: newTLSClientCertificate(t, newTestPKI(t))},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, state := newMockCMPServer(t, pki, password, nil, mockOptions{CertReqID: -1, TLSClientCAs: clientCAs})
			defer server.Close()
			request := mTLSEnrollmentRequest(t, pki, server, password)
			request.TLSClientCertificate = test.certificate
			_, err := NewClient().EnrollP10CR(context.Background(), request)
			var protocolErr *Error
			if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorKindRetryable {
				t.Fatalf("expected a retryable transport error, got %v", err)
			}
			if state.count() != 0 {
				t.Fatalf("expected the server to refuse the connection before reading CMP, got %d messages", state.count())
			}
		})
	}
}
