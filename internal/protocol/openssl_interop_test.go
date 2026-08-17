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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// opensslMockPassword is the shared secret the OpenSSL mock server is started with.
const opensslMockPassword = "cmp-issuer-interop-secret"

// opensslMockReference is the PasswordBasedMac reference the OpenSSL mock server expects.
const opensslMockReference = "cmp-issuer-interop-ref"

// requireOpenSSLCMP skips the test unless an OpenSSL build with a usable CMP mock server is present.
func requireOpenSSLCMP(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("OPENSSL_BIN")
	if binary == "" {
		binary = "openssl"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		t.Skipf("openssl is not installed, skipping the CMP interoperability test: %v", err)
	}
	help, err := exec.Command(path, "cmp", "-help").CombinedOutput()
	if err != nil && len(help) == 0 {
		t.Skipf("this openssl build has no cmp application, skipping: %v", err)
	}
	for _, option := range []string{"-port", "-poll_count", "-check_after", "-srv_secret"} {
		if !bytes.Contains(help, []byte(option)) {
			t.Skipf("this openssl cmp application lacks %s, skipping", option)
		}
	}
	return path
}

// writePEM stores one PEM block for the OpenSSL mock server to read.
func writePEM(t *testing.T, dir string, name string, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// freePort reserves a local TCP port for the OpenSSL mock server.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return port
}

// startOpenSSLMockServer runs the CMP mock server built into the openssl application and returns its address.
// The mock returns the certificate given to it rather than signing the CSR, so the caller supplies a
// certificate already issued for the CSR that the test enrolls.
func startOpenSSLMockServer(t *testing.T, pki testPKI, issued *x509.Certificate, polls int) string {
	t.Helper()
	binary := requireOpenSSLCMP(t)
	dir := t.TempDir()
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(pki.CAKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPath := writePEM(t, dir, "srv_key.pem", "PRIVATE KEY", caKeyDER)
	certificatePath := writePEM(t, dir, "srv_cert.pem", "CERTIFICATE", pki.CACertificate.Raw)
	issuedPath := writePEM(t, dir, "issued.pem", "CERTIFICATE", issued.Raw)
	port := freePort(t)
	arguments := []string{
		"cmp", "-port", fmt.Sprint(port),
		"-srv_secret", "pass:" + opensslMockPassword,
		"-srv_ref", opensslMockReference,
		"-srv_cert", certificatePath,
		"-srv_key", keyPath,
		"-rsp_cert", issuedPath,
		"-poll_count", fmt.Sprint(polls),
		"-check_after", "1",
		"-max_msgs", "0",
	}
	command := exec.Command(binary, arguments...)
	output := &bytes.Buffer{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatalf("start the OpenSSL mock server: %v", err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		if t.Failed() {
			t.Logf("OpenSSL mock server output:\n%s", output.String())
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			_ = connection.Close()
			return address
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the OpenSSL mock server did not accept connections:\n%s", output.String())
	return ""
}

// newSingleConnectionProxy forwards CMP requests to an upstream server over one pooled connection.
// The OpenSSL mock server keeps a transaction per connection and reads the following messages from
// the same socket, which RFC 6712 does not require of a CMP server. The issuer opens a connection
// per protocol call because a poll normally happens in a later reconcile, so this proxy bridges that
// difference without altering a single CMP byte.
func newSingleConnectionProxy(t *testing.T, upstream string) *httptest.Server {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: time.Minute}}
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		response, err := client.Post("http://"+upstream, request.Header.Get("Content-Type"), bytes.NewReader(body))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		forwarded, err := io.ReadAll(response.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadGateway)
			return
		}
		writer.Header().Set("Content-Type", response.Header.Get("Content-Type"))
		writer.WriteHeader(response.StatusCode)
		_, _ = writer.Write(forwarded)
	}))
	t.Cleanup(proxy.Close)
	return proxy
}

// TestDeferredTransactionAgainstOpenSSLMockServer drives a delayed enrollment and a delayed
// confirmation against the CMP server built into the openssl application, an implementation that
// shares no code with the issuer or with the library used by the other tests.
func TestDeferredTransactionAgainstOpenSSLMockServer(t *testing.T) {
	pki := newTestPKI(t)
	request := baseEnrollmentRequest(t, pki, "")
	request.Protection.Password = &PasswordProtection{Reference: []byte(opensslMockReference), Secret: []byte(opensslMockPassword), IterationCount: 1024}
	request.TransactionID = []byte("openssl-interop-transaction")
	certificateRequest, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	// The mock server returns this certificate verbatim, so it must already carry the enrolled key.
	issued := issueLeaf(t, pki, certificateRequest, certificateRequest.PublicKey)
	address := startOpenSSLMockServer(t, pki, issued, 1)
	proxy := newSingleConnectionProxy(t, address)
	request.EndpointURL = proxy.URL

	client := NewClient()
	result, err := client.EnrollP10CR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if result.Pending == nil {
		t.Fatal("expected the OpenSSL mock server to answer the enrollment with waiting")
	}
	if len(result.Pending.RequestNonce) == 0 {
		t.Fatal("expected the enrollment nonce to be reported for the following polls")
	}
	polls := 0
	for result.Pending != nil {
		polls++
		if polls > 4 {
			t.Fatal("the transaction did not complete within the expected number of polls")
		}
		if result.Pending.CheckAfter > 0 {
			time.Sleep(result.Pending.CheckAfter)
		}
		result, err = client.PollP10CR(context.Background(), PollRequest{Enrollment: request, RecipNonce: result.Pending.RecipNonce, CertReqID: result.Pending.CertReqID, ResponseSigner: result.Pending.ResponseSigner, RequestNonce: result.Pending.RequestNonce})
		if err != nil {
			t.Fatalf("PollP10CR returned error after %d polls: %v", polls, err)
		}
	}
	// Reaching this point means the delayed confirmation was polled to pkiConf as well, because the
	// mock server delays certConf whenever it delays the enrollment.
	if !result.ExplicitConfirmation {
		t.Fatal("expected the transaction to be confirmed explicitly")
	}
	if len(result.Chain) == 0 {
		t.Fatal("expected an issued certificate")
	}
	if !result.Chain[0].Equal(issued) {
		t.Fatal("expected the certificate the mock server was configured to return")
	}
	if !PublicKeysEqual(certificateRequest.PublicKey, result.Chain[0].PublicKey) {
		t.Fatal("expected the issued certificate to carry the enrolled public key")
	}
}

// TestOpenSSLMockServerReportsVersion records which OpenSSL build provided the interoperability
// coverage, so a skipped or downgraded runner is visible in the test output.
func TestOpenSSLMockServerReportsVersion(t *testing.T) {
	binary := requireOpenSSLCMP(t)
	version, err := exec.Command(binary, "version").Output()
	if err != nil {
		t.Fatalf("read the openssl version: %v", err)
	}
	t.Logf("CMP interoperability coverage uses %s", strings.TrimSpace(string(version)))
}
