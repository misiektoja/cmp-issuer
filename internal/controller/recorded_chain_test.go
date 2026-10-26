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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// foreignChainFor issues a certificate for the fixture CSR from a CA that is not a configured CMP
// trust anchor, the chain a principal with write access to CMPTransaction status could record.
func foreignChainFor(t *testing.T, fixture *asyncFixture) [][]byte {
	t.Helper()
	ca, key, _ := testCertificateMaterial(t, "Foreign CA")
	leaf := certificateIssuedBy(t, fixture.request.details.CSR, ca, key)
	return [][]byte{leaf.Raw, ca.Raw}
}

// requireRecordRefused asserts a Sign call failed permanently, returned no chain, removed the record
// and sent no CMP message beyond the given counts.
func requireRecordRefused(t *testing.T, fixture *asyncFixture, bundle issuersigner.PEMBundle, err error, calls int, polls int, confirms int) {
	t.Helper()
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) || len(bundle.ChainPEM) != 0 {
		t.Fatalf("expected the recorded transaction to be refused permanently, got %+v and %v", bundle, err)
	}
	if fixture.protocol.calls != calls || fixture.protocol.polls != polls || fixture.protocol.confirms != confirms {
		t.Fatalf("unexpected CMP traffic: calls=%d polls=%d confirms=%d", fixture.protocol.calls, fixture.protocol.polls, fixture.protocol.confirms)
	}
	if fixture.transaction(t) != nil {
		t.Fatal("expected the refused transaction state to be removed")
	}
}

// TestSignRejectsRecordedChainOutsideCMPTrust verifies a recorded chain that does not chain to the
// configured CMP trust anchors is refused when a transaction resumes in either phase that consumes it,
// before any certConf is sent and without the chain reaching cert-manager.
func TestSignRejectsRecordedChainOutsideCMPTrust(t *testing.T) {
	for _, phase := range []string{cmpv1alpha1.TransactionPhaseIssued, cmpv1alpha1.TransactionPhaseConfirming} {
		t.Run(phase, func(t *testing.T) {
			fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
			requirePending(t, mustFail(fixture.sign(t)), time.Second)
			stored := fixture.transaction(t)
			stored.Status.Phase = phase
			stored.Status.IssuedChain = foreignChainFor(t, fixture)
			certReqID := int64(0)
			stored.Status.CertReqID = &certReqID
			if err := fixture.kube.Status().Update(context.Background(), stored); err != nil {
				t.Fatal(err)
			}
			bundle, err := fixture.sign(t)
			requireRecordRefused(t, fixture, bundle, err, 1, 0, 0)
		})
	}
}

// recordedIssuedTransaction writes a complete Issued record for the fixture request, as the controller
// records one, carrying a chain that the fixture CMP trust anchor issued.
func recordedIssuedTransaction(t *testing.T, fixture *asyncFixture, mutate func(*cmpv1alpha1.CMPTransactionSpec)) {
	t.Helper()
	requestDER, err := protocol.ParseCertificateRequestDER(fixture.request.details.CSR)
	if err != nil {
		t.Fatal(err)
	}
	record := &cmpv1alpha1.CMPTransaction{
		ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Namespace: testIssuerNamespace},
		Spec: cmpv1alpha1.CMPTransactionSpec{
			CertificateRequestName: testRequestName,
			CertificateRequestUID:  string(testRequestUID),
			TransactionID:          bytes.Repeat([]byte{1}, transactionIDLength),
			Deadline:               metav1.NewTime(time.Now().Add(time.Hour)),
			CSRDigest:              csrDigestHex(requestDER),
			IssuerRef:              &cmpv1alpha1.TransactionIssuerReference{Name: testIssuerName, Kind: cmpv1alpha1.TransactionIssuerKindNamespaced, UID: string(fixture.issuer.UID), Generation: fixture.issuer.Generation},
			// An Issued record is recoverable after a credential rotation, so its configuration digest
			// is required to be present rather than to match the live configuration.
			ConfigurationDigest: "recorded-at-enrollment",
			Operation:           cmpv1alpha1.TransactionOperationP10CR,
			ProtocolVersion:     cmpProtocolVersion,
		},
	}
	if mutate != nil {
		mutate(&record.Spec)
	}
	if err := fixture.kube.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.Status.Phase = cmpv1alpha1.TransactionPhaseIssued
	record.Status.IssuedChain = [][]byte{fixture.issuedCertificate(t).Raw}
	if err := fixture.kube.Status().Update(context.Background(), record); err != nil {
		t.Fatal(err)
	}
}

// TestSignRejectsRecordedTransactionWithoutBindings verifies a record that omits the CSR digest, the
// operation or the configuration digest is not resumed even when its chain is trusted, while a
// complete record is recovered without CMP traffic.
func TestSignRejectsRecordedTransactionWithoutBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*cmpv1alpha1.CMPTransactionSpec)
	}{
		{name: "csrDigest", mutate: func(spec *cmpv1alpha1.CMPTransactionSpec) { spec.CSRDigest = "" }},
		{name: "operation", mutate: func(spec *cmpv1alpha1.CMPTransactionSpec) { spec.Operation = "" }},
		{name: "configurationDigest", mutate: func(spec *cmpv1alpha1.CMPTransactionSpec) { spec.ConfigurationDigest = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAsyncFixture(t, nil)
			recordedIssuedTransaction(t, fixture, test.mutate)
			bundle, err := fixture.sign(t)
			requireRecordRefused(t, fixture, bundle, err, 0, 0, 0)
		})
	}
	t.Run("complete record", func(t *testing.T) {
		fixture := newAsyncFixture(t, nil)
		recordedIssuedTransaction(t, fixture, nil)
		bundle, err := fixture.sign(t)
		if err != nil || len(bundle.ChainPEM) == 0 {
			t.Fatalf("expected the complete record to be recovered, got %+v and %v", bundle, err)
		}
		if fixture.protocol.calls != 0 {
			t.Fatal("expected no CMP traffic for a recovered chain")
		}
	})
}

// TestSignRecoveryRequiresCMPTrust verifies an issued chain is returned only after it was validated
// against the current CMP trust anchors. Credentials may be gone, the trust Secret may not.
func TestSignRecoveryRequiresCMPTrust(t *testing.T) {
	fixture := newAsyncFixture(t, nil)
	fixture.protocol.queue = []fakeExchange{{result: protocol.EnrollmentResult{Chain: []*x509.Certificate{fixture.issuedCertificate(t)}}}}
	want, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("complete enrollment: %v", err)
	}
	trust := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testTrustSecretName, Namespace: testIssuerNamespace}}
	if err := fixture.kube.Delete(context.Background(), trust); err != nil {
		t.Fatalf("delete the trust Secret: %v", err)
	}
	_, err = fixture.sign(t)
	var issuerErr issuersigner.IssuerError
	if !errors.As(err, &issuerErr) {
		t.Fatalf("expected recovery without CMP trust to report an issuer error, got %v", err)
	}
	if fixture.transaction(t) == nil {
		t.Fatal("expected the issued transaction to be kept while the trust Secret is unavailable")
	}
	trust.Data = map[string][]byte{testCMPTrustKey: pem.EncodeToMemory(&pem.Block{Type: pemCertificateBlockType, Bytes: fixture.leaf.Raw})}
	if err := fixture.kube.Create(context.Background(), trust); err != nil {
		t.Fatalf("restore the trust Secret: %v", err)
	}
	got, err := fixture.sign(t)
	if err != nil {
		t.Fatalf("recover the issued chain once trust is restored: %v", err)
	}
	if !bytes.Equal(got.ChainPEM, want.ChainPEM) || fixture.protocol.calls != 1 {
		t.Fatal("expected the recorded chain to be returned without another enrollment")
	}
}
