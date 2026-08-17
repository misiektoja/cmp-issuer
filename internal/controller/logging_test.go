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

package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// testWorkloadDNSName is the subject alternative name of the certificate the log detail is checked against.
const testWorkloadDNSName = "workload.example.test"

// logRecorder captures what an operator would read in the controller log.
type logRecorder struct {
	buffer bytes.Buffer
	ctx    context.Context
}

// newLogRecorder captures the log of an installation that left the verbosity at its default.
func newLogRecorder() *logRecorder {
	recorder := &logRecorder{}
	recorder.ctx = log.IntoContext(context.Background(), zap.New(zap.WriteTo(&recorder.buffer)))
	return recorder
}

// newDebugLogRecorder captures the log of an installation that raised the verbosity to debug.
func newDebugLogRecorder() *logRecorder {
	recorder := &logRecorder{}
	recorder.ctx = log.IntoContext(context.Background(), zap.New(zap.WriteTo(&recorder.buffer), zap.UseDevMode(true)))
	return recorder
}

// output returns everything logged so far.
func (r *logRecorder) output() string { return r.buffer.String() }

// requireLogged fails unless every fragment appears in the captured log.
func (r *logRecorder) requireLogged(t *testing.T, fragments ...string) {
	t.Helper()
	output := r.output()
	for _, fragment := range fragments {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected %q in the controller log, got:\n%s", fragment, output)
		}
	}
}

// requireNotLogged fails when any fragment appears in the captured log.
func (r *logRecorder) requireNotLogged(t *testing.T, fragments ...string) {
	t.Helper()
	output := r.output()
	for _, fragment := range fragments {
		if strings.Contains(output, fragment) {
			t.Fatalf("did not expect %q in the controller log, got:\n%s", fragment, output)
		}
	}
}

// issuedFixture returns a signer fixture whose next exchange issues a certificate for the request.
func issuedFixture(t *testing.T) *asyncFixture {
	t.Helper()
	fixture := newAsyncFixture(t, nil)
	fixture.protocol.queue = []fakeExchange{{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{issuedCertificateFor(t, fixture.request.details.CSR)}}}}
	return fixture
}

// TestSignLogsIssuedCertificate verifies one enrollment outcome carries the detail an operator needs.
func TestSignLogsIssuedCertificate(t *testing.T) {
	recorder := newLogRecorder()
	fixture := issuedFixture(t)
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	recorder.requireLogged(t,
		`"msg":"Issued certificate"`,
		`"issuer":"CMPIssuer/`+testIssuerNamespace+"/"+testIssuerName+`"`,
		`"endpoint":"https://example.test/cmp"`,
		`"transactionID":"`,
		`"subject":"CN=workload"`,
		`"serialNumber":"2"`,
		`"notBefore":"`,
		`"notAfter":"`,
		`"issuingCA":"CN=workload"`,
		`"keyType":"ECDSA"`,
		`"keySize":256`,
		`"signatureAlgorithm":"ECDSA-SHA256"`,
		`"chainLength":1`,
		`"confirmation":"Implicit"`,
		`"duration":"`,
	)
}

// TestLogsExcludeCredentialMaterial verifies no credential value reaches the log, even at debug.
func TestLogsExcludeCredentialMaterial(t *testing.T) {
	recorder := newDebugLogRecorder()
	fixture := issuedFixture(t)
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	recorder.requireNotLogged(t, "test-shared-secret", "test-reference", "CERTIFICATE REQUEST", "PRIVATE KEY")
}

// TestDefaultVerbosityOmitsDebugDetail verifies debugging detail stays behind a raised verbosity.
func TestDefaultVerbosityOmitsDebugDetail(t *testing.T) {
	recorder := newLogRecorder()
	fixture := issuedFixture(t)
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	recorder.requireNotLogged(t, "Recorded CMP transaction before sending the first message")
}

// TestDebugVerbosityRecordsTransactionDetail verifies the debug level narrates the enrollment decisions.
func TestDebugVerbosityRecordsTransactionDetail(t *testing.T) {
	recorder := newDebugLogRecorder()
	fixture := issuedFixture(t)
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	recorder.requireLogged(t, "Recorded CMP transaction before sending the first message", "P10CR v2")
}

// TestSignLogsPollingProgress verifies a delayed enrollment reports each wait at the default verbosity.
func TestSignLogsPollingProgress(t *testing.T) {
	recorder := newLogRecorder()
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce-one", 30*time.Second)}})
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err == nil {
		t.Fatal("expected the enrollment to report waiting")
	}
	recorder.requireLogged(t,
		`"msg":"Waiting for the CMP server to issue the certificate"`,
		`"maximumPolls":60`,
		`"retryAfter":"30s"`,
		`"deadline":"`,
	)
}

// TestSignLogsResumedConfirmation verifies a confirmation resumed after a restart is visible.
func TestSignLogsResumedConfirmation(t *testing.T) {
	recorder := newLogRecorder()
	fixture := newAsyncFixture(t, nil)
	issued := issuedCertificateFor(t, fixture.request.details.CSR)
	fixture.protocol.queue = []fakeExchange{
		{result: confirmingResult(issued, "confirm-nonce")},
		{result: protocol.EnrollmentResult{PendingConfirmation: &protocol.PendingTransaction{CertReqID: protocol.ResponseCertReqIDStandard, RecipNonce: []byte("delayed-nonce"), RequestNonce: []byte("certconf-nonce"), CheckAfter: 2 * time.Second}}},
		{result: protocol.EnrollmentResult{ExplicitConfirmation: true}},
	}
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err == nil {
		t.Fatal("expected the confirmation to be delayed")
	}
	recorder.requireLogged(t, `"msg":"Waiting for the CMP server to confirm the issued certificate"`, `"retryAfter":"2s"`)
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err != nil {
		t.Fatalf("expected the resumed confirmation to complete, got %v", err)
	}
	recorder.requireLogged(t,
		`"msg":"Resumed CMP transaction"`,
		`"phase":"Confirming"`,
		`"msg":"Issued certificate"`,
		`"confirmation":"Explicit"`,
	)
}

// TestSignLogsRecoveredCertificate verifies returning a recorded certificate is reported as an outcome.
func TestSignLogsRecoveredCertificate(t *testing.T) {
	recorder := newLogRecorder()
	fixture := issuedFixture(t)
	if _, err := fixture.signer.Sign(context.Background(), fixture.request, fixture.issuer); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err != nil {
		t.Fatalf("expected the recorded chain to be returned, got %v", err)
	}
	recorder.requireLogged(t, `"msg":"Returned the certificate already recorded for this CMP transaction"`, `"subject":"CN=workload"`)
}

// TestSignLogsTypedFailure verifies a rejected enrollment names the typed CMP failure behind it.
func TestSignLogsTypedFailure(t *testing.T) {
	recorder := newLogRecorder()
	rejection := &protocol.Error{Kind: protocol.ErrorKindPermanent, Operation: "process PKIStatus", Failure: "badRequest", Err: errors.New("the server rejected the request")}
	fixture := newAsyncFixture(t, []fakeExchange{{err: rejection}})
	if _, err := fixture.signer.Sign(recorder.ctx, fixture.request, fixture.issuer); err == nil {
		t.Fatal("expected the enrollment to fail")
	}
	recorder.requireLogged(t,
		`"msg":"CMP enrollment failed"`,
		`"operation":"process PKIStatus"`,
		`"failure":"badRequest"`,
		`"classification":"Permanent"`,
	)
}

// TestCertificateLogValuesDescribeTheIssuedLeaf verifies the logged detail identifies a certificate.
func TestCertificateLogValuesDescribeTheIssuedLeaf(t *testing.T) {
	logged := certificateLogValues([]*x509.Certificate{testIssuedCertificate(t)})
	if len(logged)%2 != 0 {
		t.Fatalf("expected balanced key-value pairs, got %d values", len(logged))
	}
	values := map[string]any{}
	for index := 0; index+1 < len(logged); index += 2 {
		key, isString := logged[index].(string)
		if !isString {
			t.Fatalf("expected a string key at position %d, got %v", index, logged[index])
		}
		values[key] = logged[index+1]
	}
	if values["subject"] != "CN="+testWorkloadDNSName+",O=Example" {
		t.Fatalf("unexpected subject: %v", values["subject"])
	}
	if values["serialNumber"] != "1000" {
		t.Fatalf("unexpected serial number: %v", values["serialNumber"])
	}
	if values["keyType"] != "ECDSA" || values["keySize"] != 256 {
		t.Fatalf("unexpected key description: %v %v", values["keyType"], values["keySize"])
	}
	names, isList := values["dnsNames"].([]string)
	if !isList || len(names) != 1 || names[0] != testWorkloadDNSName {
		t.Fatalf("unexpected dnsNames: %v", values["dnsNames"])
	}
	if addresses, isList := values["ipAddresses"].([]string); !isList || len(addresses) != 1 || addresses[0] != "10.0.0.1" {
		t.Fatalf("unexpected ipAddresses: %v", values["ipAddresses"])
	}
	if values["chainLength"] != 1 {
		t.Fatalf("unexpected chainLength: %v", values["chainLength"])
	}
}

// TestIssuerLogValueNamesTheIssuerScope verifies both issuer kinds are distinguishable in the log.
func TestIssuerLogValueNamesTheIssuerScope(t *testing.T) {
	namespaced := &cmpv1alpha1.CMPIssuer{}
	namespaced.Name = testIssuerName
	namespaced.Namespace = testIssuerNamespace
	if value := issuerLogValue(namespaced); value != "CMPIssuer/"+testIssuerNamespace+"/"+testIssuerName {
		t.Fatalf("unexpected namespaced issuer value: %q", value)
	}
	cluster := &cmpv1alpha1.CMPClusterIssuer{}
	cluster.Name = testIssuerName
	if value := issuerLogValue(cluster); value != "CMPClusterIssuer/"+testIssuerName {
		t.Fatalf("unexpected cluster issuer value: %q", value)
	}
}

// testIssuedCertificate creates a leaf carrying the subject alternative names an operator expects to read.
func testIssuedCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(4096), Subject: pkix.Name{CommonName: testWorkloadDNSName, Organization: []string{"Example"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{testWorkloadDNSName}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
