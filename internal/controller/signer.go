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

// Package controller integrates the CMP signer with issuer-lib.
package controller

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

const (
	fieldOwner              = "cmp-issuer.certmanager.misiektoja.github.io"
	eventHTTPNoConfidential = "HTTPTransportNoConfidentiality"
	schemeHTTP              = "http"
)

// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmpissuers;cmpclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmpissuers/status;cmpclusterissuers/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;patch;update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Signer loads issuer credentials and delegates protected transactions to a project-owned client.
type Signer struct {
	KubeClient               client.Reader
	ProtocolClient           protocol.Client
	EventRecorder            events.EventRecorder
	ClusterResourceNamespace string
}

// SetupWithManager registers issuer-lib controllers while disabling Kubernetes CSR support.
func (s *Signer) SetupWithManager(ctx context.Context, manager ctrl.Manager) error {
	if s.KubeClient == nil {
		s.KubeClient = manager.GetAPIReader()
	}
	if s.ProtocolClient == nil {
		s.ProtocolClient = protocol.NewClient()
	}
	if s.EventRecorder == nil {
		s.EventRecorder = manager.GetEventRecorder(fieldOwner)
	}
	if s.ClusterResourceNamespace == "" {
		return fmt.Errorf("cluster resource namespace is required")
	}
	return (&controllers.CombinedController{IssuerTypes: []issuerapi.Issuer{&cmpv1alpha1.CMPIssuer{}}, ClusterIssuerTypes: []issuerapi.Issuer{&cmpv1alpha1.CMPClusterIssuer{}}, FieldOwner: fieldOwner, MaxRetryDuration: 2 * time.Minute, Check: s.Check, Sign: s.Sign, EventRecorder: s.EventRecorder, SetCAOnCertificateRequest: false, DisableKubernetesCSRController: true}).SetupWithManager(ctx, manager)
}

// Check validates local issuer configuration and credential material without inventing a network health request.
func (s *Signer) Check(ctx context.Context, issuer issuerapi.Issuer) error {
	runtimeConfiguration, configurationErr := s.loadRuntimeConfiguration(ctx, issuer)
	if configurationErr != nil {
		if configurationErr.Permanent {
			return issuersigner.PermanentError{Err: configurationErr}
		}
		return configurationErr
	}
	if runtimeConfiguration.EndpointScheme == schemeHTTP && shouldEmitHTTPWarning(issuer) {
		s.EventRecorder.Eventf(issuer, nil, corev1.EventTypeWarning, eventHTTPNoConfidential, "TransportSecurity", "CMP message authentication and integrity are active but HTTP transport confidentiality is absent")
	}
	return nil
}

// Sign forwards the approved CertificateRequest CSR and returns a leaf-first PEM chain.
func (s *Signer) Sign(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer) (issuersigner.PEMBundle, error) {
	runtimeConfiguration, configurationErr := s.loadRuntimeConfiguration(ctx, issuer)
	if configurationErr != nil {
		return issuersigner.PEMBundle{}, issuersigner.IssuerError{Err: configurationErr}
	}
	details, err := request.GetCertificateDetails()
	if err != nil {
		return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: fmt.Errorf("read CertificateRequest details: %w", err)}
	}
	requestDER, err := protocol.ParseCertificateRequestDER(details.CSR)
	if err != nil {
		return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: err}
	}
	enrollmentRequest := runtimeConfiguration.EnrollmentRequest
	enrollmentRequest.CSRDER = requestDER
	result, err := s.ProtocolClient.EnrollP10CR(ctx, enrollmentRequest)
	if err != nil {
		return issuersigner.PEMBundle{}, mapProtocolError(err)
	}
	chainPEM := make([]byte, 0, len(result.Chain)*1024)
	for _, certificate := range result.Chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return issuersigner.PEMBundle{ChainPEM: chainPEM}, nil
}

// runtimeConfiguration contains locally validated data for one issuer generation.
type runtimeConfiguration struct {
	EndpointScheme    string
	EnrollmentRequest protocol.EnrollmentRequest
}

// configurationError distinguishes immutable spec failures from retryable Secret state.
type configurationError struct {
	Permanent bool
	Operation string
	Err       error
}

// Error returns a sanitized issuer configuration error.
func (e *configurationError) Error() string { return e.Operation + ": " + e.Err.Error() }

// Unwrap exposes the underlying configuration error.
func (e *configurationError) Unwrap() error { return e.Err }

// loadRuntimeConfiguration resolves issuer scope, validates fields and reads only referenced credential Secrets.
func (s *Signer) loadRuntimeConfiguration(ctx context.Context, issuer issuerapi.Issuer) (runtimeConfiguration, *configurationError) {
	spec, namespace, err := s.issuerSpecAndNamespace(issuer)
	if err != nil {
		return runtimeConfiguration{}, permanentConfiguration("resolve issuer", err)
	}
	parsedEndpoint, err := validateSpec(spec)
	if err != nil {
		return runtimeConfiguration{}, permanentConfiguration("validate issuer spec", err)
	}
	secrets := map[string]*corev1.Secret{}
	getSecret := func(reference cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError) {
		if secret, found := secrets[reference.Name]; found {
			return secret, nil
		}
		secret := &corev1.Secret{}
		if err := s.KubeClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: reference.Name}, secret); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, retryableConfiguration("read credential Secret", fmt.Errorf("referenced Secret %q is not available", reference.Name))
			}
			return nil, retryableConfiguration("read credential Secret", err)
		}
		secrets[reference.Name] = secret
		return secret, nil
	}
	cmpTrust, configurationErr := loadTrustPool(getSecret, spec.CMPTrust.CASecretRef)
	if configurationErr != nil {
		return runtimeConfiguration{}, configurationErr
	}
	tlsRoots, configurationErr := loadTLSRoots(getSecret, spec, parsedEndpoint.Scheme)
	if configurationErr != nil {
		return runtimeConfiguration{}, configurationErr
	}
	protection, configurationErr := loadProtection(getSecret, spec.Protection)
	if configurationErr != nil {
		return runtimeConfiguration{}, configurationErr
	}
	recipient, err := protocol.ParseDistinguishedName(spec.Protocol.Recipient)
	if err != nil {
		return runtimeConfiguration{}, permanentConfiguration("parse protocol recipient", err)
	}
	var sender *pkix.Name
	if spec.Protocol.Sender != "" {
		parsedSender, err := protocol.ParseDistinguishedName(spec.Protocol.Sender)
		if err != nil {
			return runtimeConfiguration{}, permanentConfiguration("parse protocol sender", err)
		}
		sender = &parsedSender
	}
	responseCertReqID := cmpv1alpha1.P10CRResponseCertReqIDStandard
	if spec.Protocol.P10CRResponseCertReqID != nil {
		responseCertReqID = *spec.Protocol.P10CRResponseCertReqID
	}
	request := protocol.EnrollmentRequest{EndpointURL: spec.Endpoint.URL, Timeout: spec.Endpoint.Timeout.Duration, MaxResponseSize: spec.Endpoint.MaxResponseSize, Recipient: recipient, ImplicitConfirm: spec.Protocol.Confirmation == "Implicit", RejectGrantedMods: spec.Policy.GrantedModifications != cmpv1alpha1.GrantedModificationsAccept, ResponseCertReqID: responseCertReqID, Protection: protection, CMPTrust: cmpTrust, TLSRoots: tlsRoots}
	if sender != nil {
		request.Sender = sender
	}
	return runtimeConfiguration{EndpointScheme: parsedEndpoint.Scheme, EnrollmentRequest: request}, nil
}

// issuerSpecAndNamespace returns the common spec and the only permitted credential namespace.
func (s *Signer) issuerSpecAndNamespace(issuer issuerapi.Issuer) (*cmpv1alpha1.CMPIssuerSpec, string, error) {
	switch typed := issuer.(type) {
	case *cmpv1alpha1.CMPIssuer:
		if typed.Namespace == "" {
			return nil, "", fmt.Errorf("CMPIssuer namespace is empty")
		}
		return &typed.Spec, typed.Namespace, nil
	case *cmpv1alpha1.CMPClusterIssuer:
		if s.ClusterResourceNamespace == "" {
			return nil, "", fmt.Errorf("cluster resource namespace is empty")
		}
		return &typed.Spec, s.ClusterResourceNamespace, nil
	default:
		return nil, "", fmt.Errorf("unsupported issuer type %T", issuer)
	}
}

// validateSpec enforces local protocol, transport and protection constraints.
func validateSpec(spec *cmpv1alpha1.CMPIssuerSpec) (*url.URL, error) {
	endpoint, err := validateEndpoint(spec.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := validateProtocol(spec.Protocol); err != nil {
		return nil, err
	}
	if err := validateProtection(spec.Protection); err != nil {
		return nil, err
	}
	if err := validateTransport(spec.Transport, endpoint.Scheme); err != nil {
		return nil, err
	}
	if err := validateTransactionAndPolicy(spec.Transaction, spec.Policy); err != nil {
		return nil, err
	}
	return endpoint, nil
}

// validateEndpoint enforces complete bounded HTTP or HTTPS endpoint configuration.
func validateEndpoint(spec cmpv1alpha1.EndpointSpec) (*url.URL, error) {
	endpoint, err := url.Parse(spec.URL)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != schemeHTTP && endpoint.Scheme != "https") {
		return nil, fmt.Errorf("endpoint URL must be a complete HTTP or HTTPS URL")
	}
	if endpoint.User != nil || endpoint.Fragment != "" {
		return nil, fmt.Errorf("endpoint URL user information and fragments are not supported")
	}
	if spec.Timeout.Duration <= 0 || spec.MaxResponseSize < 1024 || spec.MaxResponseSize > 10485760 {
		return nil, fmt.Errorf("endpoint timeout or response size is outside supported bounds")
	}
	return endpoint, nil
}

// validateProtocol enforces the synchronous CMPv2 P10CR milestone settings.
func validateProtocol(spec cmpv1alpha1.ProtocolSpec) error {
	if spec.Version != 2 || spec.InitialEnrollment != cmpv1alpha1.InitialEnrollmentP10CR {
		return fmt.Errorf("only CMPv2 P10CR initial enrollment is implemented")
	}
	if spec.CertProfile != "" {
		return fmt.Errorf("certProfile is reserved until its CMP encoding is implemented")
	}
	if spec.Recipient == "" || (spec.Confirmation != "Explicit" && spec.Confirmation != "Implicit") {
		return fmt.Errorf("recipient and a supported confirmation policy are required")
	}
	if spec.P10CRResponseCertReqID != nil && *spec.P10CRResponseCertReqID != cmpv1alpha1.P10CRResponseCertReqIDStandard && *spec.P10CRResponseCertReqID != cmpv1alpha1.P10CRResponseCertReqIDLegacyZero {
		return fmt.Errorf("p10cr response certReqId must be -1 or 0")
	}
	return nil
}

// validateProtection enforces the selected discriminated protection configuration.
func validateProtection(spec cmpv1alpha1.ProtectionSpec) error {
	switch spec.Type {
	case cmpv1alpha1.ProtectionTypePasswordBasedMac:
		if spec.PasswordBasedMac == nil || spec.Signature != nil {
			return fmt.Errorf("passwordBasedMac requires only passwordBasedMac configuration")
		}
		password := spec.PasswordBasedMac
		if password.ReferenceKey == "" || password.SecretKey == "" || password.ReferenceKey == password.SecretKey {
			return fmt.Errorf("passwordBasedMac reference and secret must use separate Secret keys")
		}
		if password.Algorithm.OWF != "SHA256" || password.Algorithm.MAC != "HMACSHA256" || password.Algorithm.IterationCount < 100 || password.Algorithm.IterationCount > 1048575 {
			return fmt.Errorf("unsupported passwordBasedMac algorithm parameters")
		}
	case cmpv1alpha1.ProtectionTypeSignature:
		if spec.Signature == nil || spec.PasswordBasedMac != nil {
			return fmt.Errorf("signature requires only signature configuration")
		}
		signature := spec.Signature
		if signature.CertificateKey == "" || signature.PrivateKeyKey == "" || signature.CertificateKey == signature.PrivateKeyKey {
			return fmt.Errorf("signature certificate and private key must use separate Secret keys")
		}
	default:
		return fmt.Errorf("unsupported protection type")
	}
	return nil
}

// validateTransport keeps TLS credentials separate and rejects unimplemented mTLS.
func validateTransport(spec cmpv1alpha1.TransportSpec, endpointScheme string) error {
	if spec.TLS != nil && spec.TLS.ClientCertificateSecretRef != nil {
		return fmt.Errorf("mTLS client certificates are reserved for a later release")
	}
	if endpointScheme == schemeHTTP && spec.TLS != nil && spec.TLS.CASecretRef != nil {
		return fmt.Errorf("TLS CA trust cannot be configured for an HTTP endpoint")
	}
	return nil
}

// validateTransactionAndPolicy enforces transaction bounds and certificate modification policy.
func validateTransactionAndPolicy(transaction cmpv1alpha1.TransactionSpec, policy cmpv1alpha1.PolicySpec) error {
	if transaction.MaximumDuration.Duration <= 0 || transaction.MinimumPollInterval.Duration <= 0 || transaction.MaximumPollInterval.Duration < transaction.MinimumPollInterval.Duration || transaction.MaximumPolls < 1 {
		return fmt.Errorf("transaction limits are invalid")
	}
	if policy.GrantedModifications != cmpv1alpha1.GrantedModificationsReject && policy.GrantedModifications != cmpv1alpha1.GrantedModificationsAccept {
		return fmt.Errorf("granted modifications policy is invalid")
	}
	return nil
}

// loadTrustPool parses the required CMP trust Secret key.
func loadTrustPool(getSecret func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError), reference cmpv1alpha1.SecretKeyReference) (*x509.CertPool, *configurationError) {
	secret, err := getSecret(cmpv1alpha1.LocalSecretReference{Name: reference.Name})
	if err != nil {
		return nil, err
	}
	data, valueErr := requiredSecretValue(secret, reference.Key)
	if valueErr != nil {
		return nil, retryableConfiguration("read CMP trust", valueErr)
	}
	certificates, parseErr := protocol.ParseCertificates(data)
	if parseErr != nil {
		return nil, retryableConfiguration("parse CMP trust", parseErr)
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

// loadTLSRoots parses optional HTTPS trust anchors.
func loadTLSRoots(getSecret func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError), spec *cmpv1alpha1.CMPIssuerSpec, scheme string) (*x509.CertPool, *configurationError) {
	if scheme != "https" || spec.Transport.TLS == nil || spec.Transport.TLS.CASecretRef == nil {
		return nil, nil
	}
	reference := *spec.Transport.TLS.CASecretRef
	secret, err := getSecret(cmpv1alpha1.LocalSecretReference{Name: reference.Name})
	if err != nil {
		return nil, err
	}
	data, valueErr := requiredSecretValue(secret, reference.Key)
	if valueErr != nil {
		return nil, retryableConfiguration("read TLS trust", valueErr)
	}
	certificates, parseErr := protocol.ParseCertificates(data)
	if parseErr != nil {
		return nil, retryableConfiguration("parse TLS trust", parseErr)
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

// loadProtection parses the selected CMP protection credential Secret.
func loadProtection(getSecret func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError), configured cmpv1alpha1.ProtectionSpec) (protocol.Protection, *configurationError) {
	if configured.PasswordBasedMac != nil {
		password := configured.PasswordBasedMac
		secret, err := getSecret(password.SecretRef)
		if err != nil {
			return protocol.Protection{}, err
		}
		reference, valueErr := requiredSecretValue(secret, password.ReferenceKey)
		if valueErr != nil {
			return protocol.Protection{}, retryableConfiguration("read PasswordBasedMac reference", valueErr)
		}
		sharedSecret, valueErr := requiredSecretValue(secret, password.SecretKey)
		if valueErr != nil {
			return protocol.Protection{}, retryableConfiguration("read PasswordBasedMac secret", valueErr)
		}
		return protocol.Protection{Password: &protocol.PasswordProtection{Reference: reference, Secret: sharedSecret, IterationCount: int(password.Algorithm.IterationCount)}}, nil
	}
	signature := configured.Signature
	secret, err := getSecret(signature.SecretRef)
	if err != nil {
		return protocol.Protection{}, err
	}
	certificateData, valueErr := requiredSecretValue(secret, signature.CertificateKey)
	if valueErr != nil {
		return protocol.Protection{}, retryableConfiguration("read bootstrap certificate", valueErr)
	}
	certificates, parseErr := protocol.ParseCertificates(certificateData)
	if parseErr != nil || len(certificates) != 1 {
		if parseErr == nil {
			parseErr = fmt.Errorf("bootstrap certificate key must contain exactly one certificate")
		}
		return protocol.Protection{}, retryableConfiguration("parse bootstrap certificate", parseErr)
	}
	privateKeyData, valueErr := requiredSecretValue(secret, signature.PrivateKeyKey)
	if valueErr != nil {
		return protocol.Protection{}, retryableConfiguration("read bootstrap private key", valueErr)
	}
	privateKey, parseErr := protocol.ParseSigner(privateKeyData)
	if parseErr != nil {
		return protocol.Protection{}, retryableConfiguration("parse bootstrap private key", parseErr)
	}
	if parseErr := protocol.ValidateSignerCertificate(privateKey, certificates[0]); parseErr != nil {
		return protocol.Protection{}, retryableConfiguration("validate bootstrap key pair", parseErr)
	}
	var chain []*x509.Certificate
	if signature.ChainKey != "" {
		chainData, valueErr := requiredSecretValue(secret, signature.ChainKey)
		if valueErr != nil {
			return protocol.Protection{}, retryableConfiguration("read bootstrap chain", valueErr)
		}
		chain, parseErr = protocol.ParseCertificates(chainData)
		if parseErr != nil {
			return protocol.Protection{}, retryableConfiguration("parse bootstrap chain", parseErr)
		}
	}
	return protocol.Protection{Signature: &protocol.SignatureProtection{PrivateKey: privateKey, Certificate: certificates[0], Chain: chain}}, nil
}

// requiredSecretValue returns a copied non-empty Secret value without formatting it into an error.
func requiredSecretValue(secret *corev1.Secret, key string) ([]byte, error) {
	value, found := secret.Data[key]
	if !found || len(value) == 0 {
		return nil, fmt.Errorf("required key %q is absent or empty", key)
	}
	return append([]byte(nil), value...), nil
}

// shouldEmitHTTPWarning returns true once per issuer generation before readiness is established.
func shouldEmitHTTPWarning(issuer issuerapi.Issuer) bool {
	ready := conditions.GetIssuerStatusCondition(issuer.GetConditions(), issuerapi.IssuerConditionTypeReady)
	return ready == nil || ready.ObservedGeneration < issuer.GetGeneration() || ready.Status != metav1.ConditionTrue
}

// mapProtocolError maps structured protocol failures into issuer-lib retry contracts.
func mapProtocolError(err error) error {
	var protocolError *protocol.Error
	if !errors.As(err, &protocolError) {
		return err
	}
	switch protocolError.Kind {
	case protocol.ErrorKindPermanent, protocol.ErrorKindSecurity:
		return issuersigner.PermanentError{Err: protocolError}
	case protocol.ErrorKindPending:
		return issuersigner.PermanentError{Err: fmt.Errorf("durable asynchronous CMP transactions are not enabled: %w", protocolError)}
	case protocol.ErrorKindRetryable:
		return protocolError
	default:
		return issuersigner.PermanentError{Err: fmt.Errorf("unknown protocol error classification: %w", protocolError)}
	}
}

// permanentConfiguration constructs an immutable issuer configuration failure.
func permanentConfiguration(operation string, err error) *configurationError {
	return &configurationError{Permanent: true, Operation: operation, Err: err}
}

// retryableConfiguration constructs a Secret-backed issuer configuration failure.
func retryableConfiguration(operation string, err error) *configurationError {
	return &configurationError{Permanent: false, Operation: operation, Err: err}
}
