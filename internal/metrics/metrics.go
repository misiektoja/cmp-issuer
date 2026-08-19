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

// Package metrics publishes the enrollment counters and histograms of the CMP signer on the metrics
// endpoint the manager already serves.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	controllermetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// namespace prefixes every metric this project publishes.
const namespace = "cmp_issuer"

const (
	// OperationEnrollment labels work that obtains a certificate for the first time.
	OperationEnrollment = "enrollment"
	// OperationRenewal labels a re-enrollment cert-manager started for a certificate it already holds.
	OperationRenewal = "renewal"
	// ResultIssued labels an attempt that returned a certificate.
	ResultIssued = "issued"
	// ResultFailed labels an attempt that ended in a failure instead of a certificate.
	ResultFailed = "failed"
)

// Labels identify the issuer an enrollment metric belongs to and whether it renewed a certificate.
type Labels struct {
	IssuerKind string
	Issuer     string
	Operation  string
}

// values renders the labels every enrollment metric shares, in the order they are declared.
func (l Labels) values() []string { return []string{l.IssuerKind, l.Issuer, l.Operation} }

// complete reports whether the labels identify an issuer, so an unlabelled series is never published.
func (l Labels) complete() bool { return l.IssuerKind != "" && l.Issuer != "" && l.Operation != "" }

var sharedLabels = []string{"issuer_kind", "issuer", "operation"}

var (
	enrollmentTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "enrollment_total",
		Help:      "Completed enrollment attempts by issuer, by whether they renewed a certificate and by outcome. A wait for a CMP server that has not answered yet is not an attempt and is counted by cmp_issuer_enrollment_polls_total instead.",
	}, append(append([]string{}, sharedLabels...), "result"))

	enrollmentDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "enrollment_duration_seconds",
		Help:      "Time from recording a CMP transaction to its outcome, including every poll and confirmation wait in between.",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600},
	}, append(append([]string{}, sharedLabels...), "result"))

	enrollmentFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "enrollment_failures_total",
		Help:      "Failed enrollment attempts by the CMP failure that ended them and by whether that failure is retried.",
	}, append(append([]string{}, sharedLabels...), "failure", "classification"))

	enrollmentPolls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "enrollment_polls_total",
		Help:      "Waits for a CMP server that accepted a request but has not yet returned or confirmed the certificate.",
	}, sharedLabels)

	enrollmentConfirmations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "enrollment_confirmations_total",
		Help:      "Enrollments completed by confirmation type, Explicit when the server required certConf and Implicit when it granted confirmation itself.",
	}, append(append([]string{}, sharedLabels...), "confirmation"))
)

// init publishes the collectors on the registry the manager's metrics endpoint serves.
func init() {
	controllermetrics.Registry.MustRegister(enrollmentTotal, enrollmentDuration, enrollmentFailures, enrollmentPolls, enrollmentConfirmations)
}

// RecordOutcome counts one completed enrollment attempt and observes how long it took to reach that outcome.
func RecordOutcome(labels Labels, result string, elapsed time.Duration) {
	if !labels.complete() {
		return
	}
	values := append(labels.values(), result)
	enrollmentTotal.WithLabelValues(values...).Inc()
	enrollmentDuration.WithLabelValues(values...).Observe(elapsed.Seconds())
}

// RecordFailure counts one enrollment failure under the CMP failure name and retry classification behind it.
func RecordFailure(labels Labels, failure string, classification string) {
	if !labels.complete() {
		return
	}
	enrollmentFailures.WithLabelValues(append(labels.values(), failure, classification)...).Inc()
}

// RecordPoll counts one wait for a CMP server that has not answered yet.
func RecordPoll(labels Labels) {
	if !labels.complete() {
		return
	}
	enrollmentPolls.WithLabelValues(labels.values()...).Inc()
}

// RecordConfirmation counts one enrollment completed under the given CMP confirmation type.
func RecordConfirmation(labels Labels, confirmation string) {
	if !labels.complete() {
		return
	}
	enrollmentConfirmations.WithLabelValues(append(labels.values(), confirmation)...).Inc()
}
