/*
Copyright 2026 The cmp-issuer Authors.

SPDX-License-Identifier: GPL-3.0-only

This file is part of cmp-issuer.

cmp-issuer is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3.

cmp-issuer is distributed in the hope that it will be useful but WITHOUT ANY
WARRANTY. See the GNU General Public License for more details.
*/

package protocol

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tsaarni/go-pkicmp/server"
)

// deferredCA is a certificate authority that answers waiting until the configured number of polls
// has been reached, which is how a CA with an approval queue behaves.
type deferredCA struct {
	mu sync.Mutex
	// pki supplies the signing key and issuer certificate.
	pki testPKI
	// waits is the number of poll requests answered with waiting before the certificate is issued.
	waits int
	// checkAfter is the interval the CA asks the client to wait.
	checkAfter time.Duration
	// polls counts the poll requests the CA has answered.
	polls int
	// template retains the request so the deferred issuance signs the original identity.
	template *x509.Certificate
}

// IssueCertificate defers every request so that the client has to poll for the outcome.
func (c *deferredCA) IssueCertificate(_ context.Context, _ server.RequestType, template *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.template = template
	return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: c.checkAfter, PollRef: "approval-queue"}}, nil
}

// CheckPending issues the certificate once the configured number of polls has been answered.
func (c *deferredCA) CheckPending(_ context.Context, _ string, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.polls++
	if c.polls <= c.waits {
		return &server.Response{Waiting: &server.WaitingResponse{CheckAfter: c.checkAfter, PollRef: "approval-queue"}}, nil
	}
	template := c.template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template.SerialNumber = serialNumber
	template.NotBefore = time.Now().Add(-time.Minute)
	template.NotAfter = time.Now().Add(time.Hour)
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, c.pki.CACertificate, template.PublicKey, c.pki.CAKey)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, err
	}
	return &server.Response{Certificate: certificate, CACerts: []*x509.Certificate{c.pki.CACertificate}}, nil
}

// newDeferredCMPServer starts a CMP server that defers issuance to an approval queue.
func newDeferredCMPServer(t *testing.T, pki testPKI, password []byte, waits int, checkAfter time.Duration) (*httptest.Server, *deferredCA) {
	t.Helper()
	authority := &deferredCA{pki: pki, waits: waits, checkAfter: checkAfter}
	lookup := server.SecretLookupFunc(func(_ pkix.Name, _ []byte) ([]byte, error) { return password, nil })
	handler := server.NewCAServer(authority, nil, server.WithSigner(pki.CAKey, pki.CACertificate), server.WithSecretLookup(lookup), server.WithSender(pki.CACertificate.Subject))
	return httptest.NewServer(handler), authority
}

// TestDeferredIssuanceAgainstCMPServer verifies the polling flow against an independent CMP server.
func TestDeferredIssuanceAgainstCMPServer(t *testing.T) {
	pki := newTestPKI(t)
	password := []byte("test-shared-secret")
	// The authority enforces its own wait between polls, so the interval is kept short enough to
	// keep the test fast while still exercising the rate limit a real server applies.
	pollInterval := 20 * time.Millisecond
	endpoint, authority := newDeferredCMPServer(t, pki, password, 2, pollInterval)
	defer endpoint.Close()

	request := baseEnrollmentRequest(t, pki, endpoint.URL)
	request.Protection.Password = &PasswordProtection{Reference: []byte("test-reference"), Secret: password, IterationCount: 1024}
	request.TransactionID = []byte("deferred-txn-0001")
	request.ResponseCertReqID = nil

	client := NewClient()
	result, err := client.EnrollP10CR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if result.Pending == nil {
		t.Fatal("expected the deferred authority to return a waiting response")
	}

	polls := 0
	for result.Pending != nil {
		polls++
		if polls > 5 {
			t.Fatal("the transaction did not complete within the expected number of polls")
		}
		time.Sleep(2 * pollInterval)
		poll := PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner}
		result, err = client.PollP10CR(context.Background(), poll)
		if err != nil {
			t.Fatalf("poll %d returned error: %v", polls, err)
		}
		if result.Pending != nil && result.Pending.CheckAfter < time.Second {
			t.Fatalf("expected the server to request at least the one second pollRep floor, got %s", result.Pending.CheckAfter)
		}
	}
	if polls != authority.waits+1 {
		t.Fatalf("expected %d polls, got %d", authority.waits+1, polls)
	}
	if len(result.Chain) == 0 {
		t.Fatal("expected an issued chain")
	}
	if !result.ExplicitConfirmation {
		t.Fatal("expected the deferred transaction to be confirmed explicitly")
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if !PublicKeysEqual(csr.PublicKey, result.Chain[0].PublicKey) {
		t.Fatal("the issued certificate does not carry the requested public key")
	}
}
