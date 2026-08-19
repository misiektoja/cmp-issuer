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
	"errors"
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	controllermetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/metrics"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// labelIssuerKind names the label every enrollment metric carries the issuer scope in.
const labelIssuerKind = "issuer_kind"

// labelOperation names the label that separates a first enrollment from a renewal.
const labelOperation = "operation"

// labelResult names the label that separates an issued enrollment from a failed one.
const labelResult = "result"

// metricValue reads one published series, returning zero when nothing has been recorded for it yet.
func metricValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := controllermetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			present := map[string]string{}
			for _, label := range metric.GetLabel() {
				present[label.GetName()] = label.GetValue()
			}
			matched := true
			for name, want := range labels {
				if present[name] != want {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			if counter := metric.GetCounter(); counter != nil {
				return counter.GetValue()
			}
			if histogram := metric.GetHistogram(); histogram != nil {
				return float64(histogram.GetSampleCount())
			}
		}
	}
	return 0
}

// requireMetricIncrement fails unless running the body moved one published series by exactly one.
func requireMetricIncrement(t *testing.T, name string, labels map[string]string, body func()) {
	t.Helper()
	before := metricValue(t, name, labels)
	body()
	if delta := metricValue(t, name, labels) - before; delta != 1 {
		t.Fatalf("expected %s%v to move by 1, moved by %v", name, labels, delta)
	}
}

// TestSignCountsIssuedEnrollment verifies an enrollment that returns a certificate is counted once as issued.
func TestSignCountsIssuedEnrollment(t *testing.T) {
	fixture := issuedFixture(t)
	labels := map[string]string{labelIssuerKind: issuerKindNamespaced, "issuer": testIssuerNamespace + "/" + testIssuerName, labelOperation: metrics.OperationEnrollment, labelResult: metrics.ResultIssued}
	requireMetricIncrement(t, "cmp_issuer_enrollment_total", labels, func() {
		if _, err := fixture.sign(t); err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
	})
}

// TestSignObservesIssuedEnrollmentDuration verifies the duration histogram records the same outcome.
func TestSignObservesIssuedEnrollmentDuration(t *testing.T) {
	fixture := issuedFixture(t)
	labels := map[string]string{"issuer": testIssuerNamespace + "/" + testIssuerName, labelOperation: metrics.OperationEnrollment, labelResult: metrics.ResultIssued}
	requireMetricIncrement(t, "cmp_issuer_enrollment_duration_seconds", labels, func() {
		if _, err := fixture.sign(t); err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
	})
}

// TestSignCountsImplicitConfirmation verifies the confirmation type a server granted is counted.
func TestSignCountsImplicitConfirmation(t *testing.T) {
	fixture := issuedFixture(t)
	labels := map[string]string{labelOperation: metrics.OperationEnrollment, "confirmation": confirmationImplicit}
	requireMetricIncrement(t, "cmp_issuer_enrollment_confirmations_total", labels, func() {
		if _, err := fixture.sign(t); err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
	})
}

// TestSignCountsRenewalSeparatelyFromEnrollment verifies a cert-manager renewal is not counted as a first enrollment.
func TestSignCountsRenewalSeparatelyFromEnrollment(t *testing.T) {
	fixture := issuedFixture(t)
	fixture.request.Annotations = map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "4"}
	renewal := map[string]string{labelIssuerKind: issuerKindNamespaced, labelOperation: metrics.OperationRenewal, labelResult: metrics.ResultIssued}
	enrollment := map[string]string{labelIssuerKind: issuerKindNamespaced, labelOperation: metrics.OperationEnrollment, labelResult: metrics.ResultIssued}
	before := metricValue(t, "cmp_issuer_enrollment_total", enrollment)
	requireMetricIncrement(t, "cmp_issuer_enrollment_total", renewal, func() {
		if _, err := fixture.sign(t); err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
	})
	if after := metricValue(t, "cmp_issuer_enrollment_total", enrollment); after != before {
		t.Fatalf("a renewal was also counted as an enrollment, %v became %v", before, after)
	}
}

// TestSignCountsFailedEnrollmentWithItsCMPFailure verifies a rejection is counted under the failure that caused it.
func TestSignCountsFailedEnrollmentWithItsCMPFailure(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{err: &protocol.Error{Kind: protocol.ErrorKindPermanent, Operation: testCMPOperation, Failure: testCMPFailure}}})
	outcome := map[string]string{labelIssuerKind: issuerKindNamespaced, labelOperation: metrics.OperationEnrollment, labelResult: metrics.ResultFailed}
	failure := map[string]string{labelOperation: metrics.OperationEnrollment, "failure": testCMPFailure, "classification": "Permanent"}
	requireMetricIncrement(t, "cmp_issuer_enrollment_total", outcome, func() {
		requireMetricIncrement(t, "cmp_issuer_enrollment_failures_total", failure, func() {
			if _, err := fixture.sign(t); err == nil {
				t.Fatal("expected Sign to fail")
			}
		})
	})
}

// TestSignCountsPollWithoutCountingAnOutcome verifies a server that has not answered yet is a wait, not a failure.
func TestSignCountsPollWithoutCountingAnOutcome(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: protocol.EnrollmentResult{Pending: &protocol.PendingTransaction{CertReqID: 0, RecipNonce: []byte("nonce")}}}})
	polls := map[string]string{labelIssuerKind: issuerKindNamespaced, labelOperation: metrics.OperationEnrollment}
	failed := map[string]string{labelIssuerKind: issuerKindNamespaced, labelOperation: metrics.OperationEnrollment, labelResult: metrics.ResultFailed}
	before := metricValue(t, "cmp_issuer_enrollment_total", failed)
	requireMetricIncrement(t, "cmp_issuer_enrollment_polls_total", polls, func() {
		if _, err := fixture.sign(t); err == nil {
			t.Fatal("expected Sign to report the transaction as pending")
		}
	})
	if after := metricValue(t, "cmp_issuer_enrollment_total", failed); after != before {
		t.Fatalf("a poll was counted as a failed enrollment, %v became %v", before, after)
	}
}

// TestEnrollmentOperationReadsTheCertificateRevision verifies which revisions count as a renewal.
func TestEnrollmentOperationReadsTheCertificateRevision(t *testing.T) {
	for name, testCase := range map[string]struct {
		annotations map[string]string
		expected    string
	}{
		"no annotation":     {annotations: nil, expected: metrics.OperationEnrollment},
		"first revision":    {annotations: map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "1"}, expected: metrics.OperationEnrollment},
		"second revision":   {annotations: map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "2"}, expected: metrics.OperationRenewal},
		"later revision":    {annotations: map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "17"}, expected: metrics.OperationRenewal},
		"unreadable value":  {annotations: map[string]string{certmanagerv1.CertificateRequestRevisionAnnotationKey: "later"}, expected: metrics.OperationEnrollment},
		"unrelated request": {annotations: map[string]string{"example.test/revision": "9"}, expected: metrics.OperationEnrollment},
	} {
		t.Run(name, func(t *testing.T) {
			request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName, Annotations: testCase.annotations}}
			if operation := enrollmentOperation(request); operation != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, operation)
			}
		})
	}
}

// TestEnrollmentMetricLabelsNameTheIssuerScope verifies a cluster issuer is labelled without a namespace.
func TestEnrollmentMetricLabelsNameTheIssuerScope(t *testing.T) {
	request := &fakeCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: testRequestName}}
	namespaced := enrollmentMetricLabels(&cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}}, request)
	if namespaced.IssuerKind != issuerKindNamespaced || namespaced.Issuer != testIssuerNamespace+"/"+testIssuerName {
		t.Fatalf("unexpected namespaced issuer labels: %+v", namespaced)
	}
	clustered := enrollmentMetricLabels(&cmpv1alpha1.CMPClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName}}, request)
	if clustered.IssuerKind != issuerKindCluster || clustered.Issuer != testIssuerName {
		t.Fatalf("unexpected cluster issuer labels: %+v", clustered)
	}
}

// TestFailureLabelsClassifyEveryFailureShape verifies each error the signer returns gets a bounded label pair.
func TestFailureLabelsClassifyEveryFailureShape(t *testing.T) {
	failure, classification := failureLabels(&protocol.Error{Kind: protocol.ErrorKindSecurity, Failure: "signerNotTrusted"})
	if failure != "signerNotTrusted" || classification != "Security" {
		t.Fatalf("unexpected CMP failure labels: %q %q", failure, classification)
	}
	failure, classification = failureLabels(&configurationError{Permanent: true, Operation: "resolve issuer"})
	if failure != failureIssuerConfiguration || classification != string(protocol.ErrorKindPermanent) {
		t.Fatalf("unexpected configuration failure labels: %q %q", failure, classification)
	}
	failure, classification = failureLabels(errors.New("connection reset"))
	if failure != failureUnclassified || classification != classificationUnknown {
		t.Fatalf("unexpected unclassified failure labels: %q %q", failure, classification)
	}
}
