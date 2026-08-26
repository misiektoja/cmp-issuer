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
	"sync"
	"testing"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// opensslMockPassword is the shared secret the OpenSSL mock server is started with.
const opensslMockPassword = "cmp-issuer-interop-secret"

// opensslMockReference is the PasswordBasedMac reference the OpenSSL mock server expects.
const opensslMockReference = "cmp-issuer-interop-ref"

// opensslPortOption selects the OpenSSL mock server listen port.
const opensslPortOption = "-port"

// opensslReferenceCertificateOption names the mock server option that validates the oldCertID a KUR
// carries. OpenSSL added it in 3.2, so an older build cannot provide this coverage.
const opensslReferenceCertificateOption = "-ref_cert"

// requireOpenSSLCMP skips the test unless an OpenSSL build with a usable CMP mock server and every extra option is present.
func requireOpenSSLCMP(t *testing.T, extra ...string) string {
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
	for _, option := range append([]string{opensslPortOption, "-poll_count", "-check_after", "-srv_secret"}, extra...) {
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
		"cmp", opensslPortOption, fmt.Sprint(port),
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

// startOpenSSLKURMockServer runs an independently authenticated signature-protected KUR responder.
func startOpenSSLKURMockServer(t *testing.T, pki testPKI, current *x509.Certificate, issued *x509.Certificate) string {
	t.Helper()
	binary := requireOpenSSLCMP(t, opensslReferenceCertificateOption)
	dir := t.TempDir()
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(pki.CAKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPath := writePEM(t, dir, "srv_key.pem", "PRIVATE KEY", caKeyDER)
	certificatePath := writePEM(t, dir, "srv_cert.pem", "CERTIFICATE", pki.CACertificate.Raw)
	trustPath := writePEM(t, dir, "srv_trusted.pem", "CERTIFICATE", pki.CACertificate.Raw)
	currentPath := writePEM(t, dir, "ref_cert.pem", "CERTIFICATE", current.Raw)
	issuedPath := writePEM(t, dir, "issued.pem", "CERTIFICATE", issued.Raw)
	port := freePort(t)
	arguments := []string{"cmp", opensslPortOption, fmt.Sprint(port), "-srv_cert", certificatePath, "-srv_key", keyPath, "-srv_trusted", trustPath, opensslReferenceCertificateOption, currentPath, "-rsp_cert", issuedPath, "-rsp_extracerts", certificatePath, "-max_msgs", "0"}
	command := exec.Command(binary, arguments...)
	output := &bytes.Buffer{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatalf("start the OpenSSL KUR mock server: %v", err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		if t.Failed() {
			t.Logf("OpenSSL KUR mock server output:\n%s", output.String())
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
	t.Fatalf("the OpenSSL KUR mock server did not accept connections:\n%s", output.String())
	return ""
}

// forwardedMessages records the CMP requests a proxy passed to the OpenSSL mock server.
type forwardedMessages struct {
	mu       sync.Mutex
	messages [][]byte
}

// add stores one forwarded request exactly as it was received.
func (f *forwardedMessages) add(requestDER []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, append([]byte(nil), requestDER...))
}

// at returns the forwarded request at the given position, or nil when fewer were forwarded.
func (f *forwardedMessages) at(index int) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if index >= len(f.messages) {
		return nil
	}
	return f.messages[index]
}

// newSingleConnectionProxy forwards CMP requests to an upstream server over one pooled connection.
// The OpenSSL mock server keeps a transaction per connection and reads the following messages from
// the same socket, which RFC 6712 does not require of a CMP server. The issuer opens a connection
// per protocol call because a poll normally happens in a later reconcile, so this proxy bridges that
// difference without altering a single CMP byte.
func newSingleConnectionProxy(t *testing.T, upstream string) (*httptest.Server, *forwardedMessages) {
	t.Helper()
	forwarded := &forwardedMessages{}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: time.Minute}}
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		forwarded.add(body)
		response, err := client.Post("http://"+upstream, request.Header.Get("Content-Type"), bytes.NewReader(body))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		relayed, err := io.ReadAll(response.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadGateway)
			return
		}
		writer.Header().Set("Content-Type", response.Header.Get("Content-Type"))
		writer.WriteHeader(response.StatusCode)
		_, _ = writer.Write(relayed)
	}))
	t.Cleanup(proxy.Close)
	return proxy, forwarded
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
	proxy, _ := newSingleConnectionProxy(t, address)
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
	if len(result.Chain) == 0 {
		t.Fatal("expected an issued certificate")
	}
	if result.PendingConfirmation == nil {
		t.Fatal("expected the issued certificate to await confirmation")
	}
	// The mock server delays certConf whenever it delays the enrollment, so completing this drives
	// the delayed confirmation through pollReq to pkiConf.
	result, err = confirmToCompletion(t, client, request, result)
	if err != nil {
		t.Fatalf("confirmation returned error: %v", err)
	}
	if !result.ExplicitConfirmation {
		t.Fatal("expected the transaction to be confirmed explicitly")
	}
	if !result.Chain[0].Equal(issued) {
		t.Fatal("expected the certificate the mock server was configured to return")
	}
	if !PublicKeysEqual(certificateRequest.PublicKey, result.Chain[0].PublicKey) {
		t.Fatal("expected the issued certificate to carry the enrolled public key")
	}
}

// TestPinnedTransactionAgainstOpenSSLMockServer verifies that the transaction identifier a caller
// pins so it can resume the transaction later is the identifier an independent CMP implementation
// sees on the wire, and that the exchange still yields the certificate.
func TestPinnedTransactionAgainstOpenSSLMockServer(t *testing.T) {
	pki := newTestPKI(t)
	request := baseEnrollmentRequest(t, pki, "")
	request.Protection.Password = &PasswordProtection{Reference: []byte(opensslMockReference), Secret: []byte(opensslMockPassword), IterationCount: 1024}
	request.TransactionID = []byte("openssl-pinned-transaction")
	certificateRequest, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	// The mock server returns this certificate verbatim, so it must already carry the enrolled key.
	issued := issueLeaf(t, pki, certificateRequest, certificateRequest.PublicKey)
	proxy, forwarded := newSingleConnectionProxy(t, startOpenSSLMockServer(t, pki, issued, 0))
	request.EndpointURL = proxy.URL

	result, err := NewClient().EnrollP10CR(context.Background(), request)
	if err != nil {
		t.Fatalf("EnrollP10CR returned error: %v", err)
	}
	if len(result.Chain) == 0 || !result.Chain[0].Equal(issued) {
		t.Fatal("expected the certificate the mock server was configured to return")
	}
	sent, err := pkicmp.ParsePKIMessage(forwarded.at(0))
	if err != nil {
		t.Fatalf("parse the message OpenSSL accepted: %v", err)
	}
	if !bytes.Equal(sent.Header.TransactionID, request.TransactionID) {
		t.Fatal("expected the pinned transaction identifier to reach the server unchanged")
	}
}

// TestKURAgainstOpenSSLMockServer verifies new-key and same-key CRMF updates with an independent implementation.
func TestKURAgainstOpenSSLMockServer(t *testing.T) {
	for _, test := range []struct {
		name      string
		rotateKey bool
	}{
		{name: "new key", rotateKey: true},
		{name: "same key", rotateKey: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			request := kurEnrollmentRequest(t, pki, "", test.rotateKey)
			certificateRequest, err := x509.ParseCertificateRequest(request.CSRDER)
			if err != nil {
				t.Fatalf("parse KUR CSR: %v", err)
			}
			issued := issueLeaf(t, pki, certificateRequest, request.RequestedPrivateKey.Public())
			proxy, forwarded := newSingleConnectionProxy(t, startOpenSSLKURMockServer(t, pki, request.Protection.Signature.Certificate, issued))
			request.EndpointURL = proxy.URL
			client := NewClient()
			result, err := client.EnrollKUR(context.Background(), request)
			if err == nil {
				result, err = confirmToCompletion(t, client, request, result)
			}
			if err != nil {
				t.Fatalf("OpenSSL KUR returned error: %v", err)
			}
			if len(result.Chain) == 0 || !result.Chain[0].Equal(issued) {
				t.Fatal("expected the KUR certificate configured on the OpenSSL mock server")
			}
			sent, err := pkicmp.ParsePKIMessage(forwarded.at(0))
			if err != nil || sent.Body.Type != pkicmp.BodyTypeKUR {
				t.Fatalf("expected OpenSSL to accept a KUR body, got %v and %v", sent, err)
			}
		})
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
