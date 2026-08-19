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
	"context"
	"errors"
	"strconv"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/metrics"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

const (
	// issuerKindNamespaced names the namespaced issuer kind in logs and metric labels.
	issuerKindNamespaced = "CMPIssuer"
	// issuerKindCluster names the cluster-scoped issuer kind in logs and metric labels.
	issuerKindCluster = "CMPClusterIssuer"
	// failureIssuerConfiguration labels a failure that never reached the CMP server.
	failureIssuerConfiguration = "issuerConfiguration"
	// failureUnclassified labels a failure that carries no CMP failure information.
	failureUnclassified = "unclassified"
	// classificationUnknown labels a failure whose retry behavior is not described by the error.
	classificationUnknown = "Unknown"
)

// enrollmentLabelsKey types the context value carrying the metric labels of the enrollment in flight.
type enrollmentLabelsKey struct{}

// withEnrollmentLabels carries the metric labels of an enrollment down the call chain, as the logger already is.
func withEnrollmentLabels(ctx context.Context, labels metrics.Labels) context.Context {
	return context.WithValue(ctx, enrollmentLabelsKey{}, labels)
}

// enrollmentLabelsFrom returns the metric labels of the enrollment in flight, or empty labels outside one.
func enrollmentLabelsFrom(ctx context.Context) metrics.Labels {
	labels, _ := ctx.Value(enrollmentLabelsKey{}).(metrics.Labels)
	return labels
}

// enrollmentMetricLabels names the issuer serving an enrollment and whether it renews a certificate.
func enrollmentMetricLabels(issuer issuerapi.Issuer, request issuersigner.CertificateRequestObject) metrics.Labels {
	if _, isCluster := issuer.(*cmpv1alpha1.CMPClusterIssuer); isCluster {
		return metrics.Labels{IssuerKind: issuerKindCluster, Issuer: issuer.GetName(), Operation: enrollmentOperation(request)}
	}
	return metrics.Labels{IssuerKind: issuerKindNamespaced, Issuer: issuer.GetNamespace() + "/" + issuer.GetName(), Operation: enrollmentOperation(request)}
}

// enrollmentOperation reports whether cert-manager raised this request to renew a certificate it already holds.
func enrollmentOperation(request issuersigner.CertificateRequestObject) string {
	// cert-manager stamps the revision a CertificateRequest will become, so anything past the first is
	// a renewal. A request written by hand carries no revision and is a first enrollment either way.
	revision, err := strconv.Atoi(request.GetAnnotations()[certmanagerv1.CertificateRequestRevisionAnnotationKey])
	if err == nil && revision > 1 {
		return metrics.OperationRenewal
	}
	return metrics.OperationEnrollment
}

// recordIssuedEnrollment records an enrollment attempt that returned a certificate and how it was confirmed.
func recordIssuedEnrollment(ctx context.Context, confirmation string, started time.Time) {
	labels := enrollmentLabelsFrom(ctx)
	metrics.RecordOutcome(labels, metrics.ResultIssued, time.Since(started))
	metrics.RecordConfirmation(labels, confirmation)
}

// recordFailedEnrollment records an enrollment attempt that ended in a failure rather than a certificate.
func recordFailedEnrollment(ctx context.Context, err error, started time.Time) {
	var pendingErr issuersigner.PendingError
	if err == nil || errors.As(err, &pendingErr) {
		// A transaction still waiting on the server has not failed, and its waits are counted elsewhere.
		return
	}
	labels := enrollmentLabelsFrom(ctx)
	metrics.RecordOutcome(labels, metrics.ResultFailed, time.Since(started))
	failure, classification := failureLabels(err)
	metrics.RecordFailure(labels, failure, classification)
}

// recordEnrollmentPoll records one wait for a CMP server that has accepted a request but not answered it.
func recordEnrollmentPoll(ctx context.Context) { metrics.RecordPoll(enrollmentLabelsFrom(ctx)) }

// failureLabels names the CMP failure that ended an enrollment and whether that failure is retried.
func failureLabels(err error) (string, string) {
	var protocolError *protocol.Error
	if errors.As(err, &protocolError) {
		return protocolError.Failure, string(protocolError.Kind)
	}
	var configurationErr *configurationError
	if errors.As(err, &configurationErr) {
		return failureIssuerConfiguration, configurationClassification(configurationErr)
	}
	return failureUnclassified, classificationUnknown
}
