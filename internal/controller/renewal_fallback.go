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
	"crypto/x509"
	"fmt"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/logging"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// renewalFallback describes why a KUR renewal uses the initial enrollment operation instead.
type renewalFallback struct {
	Reason      string
	Certificate string
	Secret      string
	// Expired is the current certificate for CurrentCertificateExpired and nil otherwise.
	Expired *x509.Certificate
}

// renewalFallbackOperation returns the initial enrollment operation an issuer falls back to when a
// KUR renewal has no usable current certificate. It returns an empty string when the issuer has no
// fallback.
func renewalFallbackOperation(issuer issuerapi.Issuer) string {
	spec, err := cmpIssuerSpec(issuer)
	if err != nil || spec.Protocol.RenewalFallback != cmpv1alpha1.RenewalFallbackInitialEnrollment || renewalOperation(spec.Protocol) != cmpv1alpha1.TransactionOperationKUR {
		return ""
	}
	return initialOperation(spec.Protocol)
}

// classifyRenewalFallback decides whether a KUR renewal falls back to the initial enrollment
// operation. It authorizes the owner chain as KUR does and reads the current Secret once. It falls back
// when the Secret is absent or when cert-manager wrote it for the Certificate without a certificate or
// with an expired one. Every other state returns nil so that KUR runs and reports its own failure.
func (s *Signer) classifyRenewalFallback(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer, now time.Time) (*renewalFallback, *configurationError) {
	certificate, configurationErr := s.authorizeOwningCertificate(ctx, request, issuer, cmpv1alpha1.TransactionOperationKUR, true)
	if configurationErr != nil {
		return nil, configurationErr
	}
	if certificate.Spec.SecretName == "" || certificate.Spec.SecretName == request.GetAnnotations()[certmanagerv1.CertificateRequestPrivateKeyAnnotationKey] {
		return nil, nil
	}
	key := types.NamespacedName{Namespace: request.GetNamespace(), Name: certificate.Spec.SecretName}
	fallback := &renewalFallback{Reason: cmpv1alpha1.RenewalFallbackCurrentCertificateMissing, Certificate: certificate.Name, Secret: key.Name}
	secret, configurationErr := s.readCurrentSecret(ctx, key)
	if configurationErr != nil {
		return nil, configurationErr
	}
	if secret == nil {
		return fallback, nil
	}
	// A Secret another tool wrote or replaced never counts as missing or expired.
	if currentSecretIssuedForCertificate(secret, certificate) != nil {
		return nil, nil
	}
	data := secret.Data[corev1.TLSCertKey]
	if len(data) == 0 {
		return fallback, nil
	}
	certificates, err := protocol.ParseCertificates(data)
	// The expiry comparison matches the KUR validity check.
	if err != nil || len(certificates) == 0 || now.Before(certificates[0].NotAfter) {
		return nil, nil
	}
	fallback.Reason = cmpv1alpha1.RenewalFallbackCurrentCertificateExpired
	fallback.Expired = certificates[0]
	return fallback, nil
}

// readCurrentSecret reads the current certificate Secret of a Certificate and returns nil without an
// error when the API server reports it absent. cert-manager writes that Secret only when an issuance
// succeeds, so waiting does not bring it back.
func (s *Signer) readCurrentSecret(ctx context.Context, key types.NamespacedName) (*corev1.Secret, *configurationError) {
	secret := &corev1.Secret{}
	if err := s.KubeClient.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, retryableConfiguration("read current certificate Secret", err)
	}
	return secret, nil
}

// currentCertificateUnavailable explains a KUR that has no current certificate to authenticate with
// and names the ways to recover.
func currentCertificateUnavailable(secretName string, state string) error {
	return fmt.Errorf("current certificate Secret %q %s, so KUR cannot authenticate: set renewalFallback to InitialEnrollment, set renewal to P10CR or recreate the Certificate", secretName, state)
}

// reportRenewalFallback logs a recorded renewal fallback and reports it in a Warning Event on the
// CertificateRequest, because the CA receives a renewal protected by the issuer credentials.
func (s *Signer) reportRenewalFallback(ctx context.Context, request issuersigner.CertificateRequestObject, operation string, fallback renewalFallback) {
	values := []any{"operation", operation, "reason", fallback.Reason, "certificate", logging.Text(fallback.Certificate), "secret", logging.Text(fallback.Secret)}
	if fallback.Expired != nil {
		values = append(values, "serialNumber", serialNumberLogValue(fallback.Expired), "notAfter", timestampLogValue(fallback.Expired.NotAfter))
	}
	log.FromContext(ctx).Info("Renewing with the initial enrollment operation instead of KUR", values...)
	resource := certificateRequestResource(request)
	if resource == nil {
		return
	}
	if fallback.Expired != nil {
		s.EventRecorder.Eventf(resource, nil, corev1.EventTypeWarning, eventRenewalFallback, "Renew", "Renewing with %s instead of KUR because the certificate in Secret %q expired at %s", operation, fallback.Secret, timestampLogValue(fallback.Expired.NotAfter))
		return
	}
	s.EventRecorder.Eventf(resource, nil, corev1.EventTypeWarning, eventRenewalFallback, "Renew", "Renewing with %s instead of KUR because Secret %q is missing or holds no certificate", operation, fallback.Secret)
}
