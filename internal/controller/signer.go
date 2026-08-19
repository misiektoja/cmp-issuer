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

// Package controller integrates the CMP signer with issuer-lib.
package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
	"sigs.k8s.io/controller-runtime/pkg/log"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/logging"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

const (
	fieldOwner              = "cmp-issuer.certmanager.misiektoja.github.io"
	eventHTTPNoConfidential = "HTTPTransportNoConfidentiality"
	schemeHTTP              = "http"
	// The polling defaults match the CRD defaults and apply when the transaction block is omitted.
	defaultMaximumDuration     = 10 * time.Minute
	defaultMinimumPollInterval = time.Second
	defaultMaximumPollInterval = 5 * time.Minute
	defaultMaximumPolls        = 60
	// cmpProtocolVersion is the CMP protocol version of every message this milestone sends.
	cmpProtocolVersion = 2
)

// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmpissuers;cmpclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmpissuers/status;cmpclusterissuers/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmptransactions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmptransactions/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;patch;update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Signer loads issuer credentials and delegates protected transactions to a project-owned client.
type Signer struct {
	KubeClient               client.Reader
	ProtocolClient           protocol.Client
	EventRecorder            events.EventRecorder
	ClusterResourceNamespace string
	transactions             *transactionStore
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
	if s.transactions == nil {
		s.transactions = &transactionStore{reader: manager.GetAPIReader(), writer: manager.GetClient()}
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
func (s *Signer) Sign(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer) (bundle issuersigner.PEMBundle, err error) {
	enrollmentStarted := time.Now()
	ctx = log.IntoContext(ctx, log.FromContext(ctx).WithValues("issuer", issuerLogValue(issuer)))
	ctx = withEnrollmentLabels(ctx, enrollmentMetricLabels(issuer, request))
	// Every way out of an enrollment is reported once, from whatever the transaction is known by then.
	defer func() {
		logEnrollmentFailure(ctx, err)
		recordFailedEnrollment(ctx, err, enrollmentStarted)
	}()
	runtimeConfiguration, configurationErr := s.loadRuntimeConfiguration(ctx, issuer)
	if configurationErr != nil {
		return issuersigner.PEMBundle{}, issuersigner.IssuerError{Err: configurationErr}
	}
	ctx = log.IntoContext(ctx, log.FromContext(ctx).WithValues("endpoint", logging.Text(runtimeConfiguration.EnrollmentRequest.EndpointURL)))
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
	limits := runtimeConfiguration.Transaction
	csrDigest := csrDigestHex(requestDER)
	transaction, err := s.transactions.load(ctx, request.GetNamespace(), request.GetName(), request.GetUID())
	if err != nil {
		return issuersigner.PEMBundle{}, err
	}
	resumed := transaction != nil
	if !resumed {
		// The transaction is recorded before the first message is sent, so that a controller restart
		// resumes this transaction instead of starting a second enrollment for the same request.
		transaction, err = s.transactions.create(ctx, request.GetNamespace(), request.GetName(), request.GetUID(), time.Now().Add(limits.MaximumDuration.Duration), transactionDetail{CSRDigest: csrDigest, IssuerRef: issuerReference(issuer), Operation: cmpv1alpha1.TransactionOperationP10CR, ProtocolVersion: cmpProtocolVersion})
		if err != nil {
			return issuersigner.PEMBundle{}, err
		}
	}
	ctx = log.IntoContext(ctx, log.FromContext(ctx).WithValues("transactionID", transactionIDLogValue(transaction.Spec.TransactionID)))
	if resumed {
		logResumedTransaction(ctx, transaction)
		if transaction.Spec.CSRDigest != "" && transaction.Spec.CSRDigest != csrDigest {
			return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: fmt.Errorf("recorded CMP transaction enrolls a different certificate signing request")}
		}
		// The transaction outlives this reconcile, so issuance is timed from the record that started it.
		if !transaction.CreationTimestamp.IsZero() {
			enrollmentStarted = transaction.CreationTimestamp.Time
		}
	} else {
		log.FromContext(ctx).V(1).Info("Recorded CMP transaction before sending the first message", "operation", enrollmentLogValue(transaction), "deadline", timestampLogValue(transaction.Spec.Deadline.Time))
	}
	if transaction.Status.Phase == cmpv1alpha1.TransactionPhaseIssued {
		return recoverIssuedChain(ctx, transaction, requestDER)
	}
	enrollmentRequest.TransactionID = transaction.Spec.TransactionID
	if transaction.Status.Phase == cmpv1alpha1.TransactionPhaseConfirming {
		return s.resumeConfirmation(ctx, transaction, enrollmentRequest, limits, requestDER, enrollmentStarted)
	}
	polled := transaction.Status.Phase == cmpv1alpha1.TransactionPhasePolling
	result, err := s.exchange(ctx, enrollmentRequest, transaction, limits)
	if err != nil {
		return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, err)
	}
	if result.Pending != nil {
		return issuersigner.PEMBundle{}, s.continuePolling(ctx, transaction, result.Pending, limits, polled)
	}
	if result.PendingConfirmation != nil {
		// The chain is recorded before certConf is sent, so an interruption during confirmation
		// resumes it instead of failing a request whose certificate the server already issued.
		if err := s.transactions.recordConfirming(ctx, transaction, result.Chain, result.PendingConfirmation); err != nil {
			return issuersigner.PEMBundle{}, err
		}
		return s.confirm(ctx, transaction, enrollmentRequest, limits, result.Chain, result.PendingConfirmation, enrollmentStarted)
	}
	// A server that granted implicit confirmation issues no certConf, so the chain is recorded here
	// before it is returned to cert-manager.
	if err := s.transactions.recordIssued(ctx, transaction, result.Chain); err != nil {
		return issuersigner.PEMBundle{}, err
	}
	logIssuedCertificate(ctx, transaction, result.Chain, confirmationImplicit, enrollmentStarted)
	recordIssuedEnrollment(ctx, confirmationImplicit, enrollmentStarted)
	return issuersigner.PEMBundle{ChainPEM: encodeChainPEM(result.Chain)}, nil
}

// resumeConfirmation continues the confirmation of a certificate an earlier reconcile already
// recorded, so a restart inside a delayed confirmation does not discard an issued certificate.
func (s *Signer) resumeConfirmation(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, enrollmentRequest protocol.EnrollmentRequest, limits cmpv1alpha1.TransactionSpec, csrDER []byte, enrollmentStarted time.Time) (issuersigner.PEMBundle, error) {
	chain, err := recordedChain(transaction, csrDER)
	if err != nil {
		return issuersigner.PEMBundle{}, err
	}
	if transaction.Status.CertReqID == nil {
		return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: fmt.Errorf("recorded CMP transaction is missing the state required to confirm")}
	}
	pending := &protocol.PendingTransaction{CertReqID: *transaction.Status.CertReqID, RecipNonce: transaction.Status.RecipNonce, RequestNonce: transaction.Status.RequestNonce}
	if len(transaction.Status.ResponseSigner) > 0 {
		signer, parseErr := x509.ParseCertificate(transaction.Status.ResponseSigner)
		if parseErr != nil {
			return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: fmt.Errorf("parse retained CMP response signer: %w", parseErr)}
		}
		pending.ResponseSigner = signer
	}
	return s.confirm(ctx, transaction, enrollmentRequest, limits, chain, pending, enrollmentStarted)
}

// confirm sends or continues the confirmation exchange and completes the transaction when the server
// answers with pkiConf.
func (s *Signer) confirm(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, enrollmentRequest protocol.EnrollmentRequest, limits cmpv1alpha1.TransactionSpec, chain []*x509.Certificate, pending *protocol.PendingTransaction, enrollmentStarted time.Time) (issuersigner.PEMBundle, error) {
	if time.Now().After(transaction.Spec.Deadline.Time) {
		return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, issuersigner.PermanentError{Err: fmt.Errorf("CMP transaction exceeded the configured maximum duration of %s", limits.MaximumDuration.Duration)})
	}
	if transaction.Status.Polls >= limits.MaximumPolls {
		return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, issuersigner.PermanentError{Err: fmt.Errorf("CMP transaction reached the configured maximum of %d polls", limits.MaximumPolls)})
	}
	log.FromContext(ctx).V(1).Info("Confirming the issued certificate", "certReqID", pending.CertReqID, "polls", transaction.Status.Polls)
	confirmRequest := protocol.ConfirmRequest{Enrollment: enrollmentRequest, Certificate: chain[0], CertReqID: pending.CertReqID, RecipNonce: pending.RecipNonce, ResponseSigner: pending.ResponseSigner, RequestNonce: pending.RequestNonce}
	result, err := s.ProtocolClient.ConfirmP10CR(ctx, confirmRequest)
	if err != nil {
		return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, err)
	}
	if result.PendingConfirmation != nil {
		return issuersigner.PEMBundle{}, s.continueConfirming(ctx, transaction, chain, result.PendingConfirmation, limits)
	}
	if err := s.transactions.recordIssued(ctx, transaction, chain); err != nil {
		return issuersigner.PEMBundle{}, err
	}
	logIssuedCertificate(ctx, transaction, chain, confirmationExplicit, enrollmentStarted)
	recordIssuedEnrollment(ctx, confirmationExplicit, enrollmentStarted)
	return issuersigner.PEMBundle{ChainPEM: encodeChainPEM(chain)}, nil
}

// continueConfirming records the state for the next confirmation poll and asks for a later retry.
func (s *Signer) continueConfirming(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, chain []*x509.Certificate, pending *protocol.PendingTransaction, limits cmpv1alpha1.TransactionSpec) error {
	transaction.Status.Polls++
	if err := s.transactions.recordConfirming(ctx, transaction, chain, pending); err != nil {
		return err
	}
	delay := pollDelay(pending.CheckAfter, limits)
	if deadlineDelay := time.Until(transaction.Spec.Deadline.Time); deadlineDelay > 0 && deadlineDelay < delay {
		delay = deadlineDelay
	}
	log.FromContext(ctx).Info("Waiting for the CMP server to confirm the issued certificate", enrollmentDeadlineValues(transaction, limits, delay)...)
	recordEnrollmentPoll(ctx)
	return issuersigner.PendingError{Err: fmt.Errorf("CMP server has not confirmed the issued certificate yet, polling again in %s", delay), RequeueAfter: delay}
}

// recoverIssuedChain returns the chain recorded for a transaction that already obtained a
// certificate, after checking that it still matches the request being signed.
func recoverIssuedChain(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, csrDER []byte) (issuersigner.PEMBundle, error) {
	chain, err := recordedChain(transaction, csrDER)
	if err != nil {
		return issuersigner.PEMBundle{}, err
	}
	log.FromContext(ctx).Info("Returned the certificate already recorded for this CMP transaction", certificateLogValues(chain)...)
	return issuersigner.PEMBundle{ChainPEM: encodeChainPEM(chain)}, nil
}

// recordedChain parses the chain a transaction recorded and rejects one that no longer belongs to the
// request being signed.
func recordedChain(transaction *cmpv1alpha1.CMPTransaction, csrDER []byte) ([]*x509.Certificate, error) {
	if len(transaction.Status.IssuedChain) == 0 {
		return nil, issuersigner.PermanentError{Err: fmt.Errorf("recorded CMP transaction reports an issued certificate without a chain")}
	}
	chain := make([]*x509.Certificate, 0, len(transaction.Status.IssuedChain))
	for _, encoded := range transaction.Status.IssuedChain {
		certificate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return nil, issuersigner.PermanentError{Err: fmt.Errorf("parse recorded CMP certificate chain: %w", parseErr)}
		}
		chain = append(chain, certificate)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, issuersigner.PermanentError{Err: fmt.Errorf("parse CertificateRequest CSR: %w", err)}
	}
	if !protocol.PublicKeysEqual(csr.PublicKey, chain[0].PublicKey) {
		return nil, issuersigner.PermanentError{Err: fmt.Errorf("recorded CMP certificate does not match the requested public key")}
	}
	return chain, nil
}

// encodeChainPEM renders a leaf-first certificate chain as concatenated PEM blocks.
func encodeChainPEM(chain []*x509.Certificate) []byte {
	chainPEM := make([]byte, 0, len(chain)*1024)
	for _, certificate := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return chainPEM
}

// csrDigestHex returns the lowercase hexadecimal SHA-256 digest that identifies an enrolled CSR.
func csrDigestHex(csrDER []byte) string {
	digest := sha256.Sum256(csrDER)
	return hex.EncodeToString(digest[:])
}

// issuerReference describes the issuer serving a transaction for the recorded transaction detail.
func issuerReference(issuer issuerapi.Issuer) cmpv1alpha1.TransactionIssuerReference {
	kind := cmpv1alpha1.TransactionIssuerKindNamespaced
	if _, isCluster := issuer.(*cmpv1alpha1.CMPClusterIssuer); isCluster {
		kind = cmpv1alpha1.TransactionIssuerKindCluster
	}
	return cmpv1alpha1.TransactionIssuerReference{Name: issuer.GetName(), Kind: kind, UID: string(issuer.GetUID())}
}

// exchange sends the enrollment request, or resumes a transaction the server answered with waiting.
func (s *Signer) exchange(ctx context.Context, enrollmentRequest protocol.EnrollmentRequest, transaction *cmpv1alpha1.CMPTransaction, limits cmpv1alpha1.TransactionSpec) (protocol.EnrollmentResult, error) {
	if time.Now().After(transaction.Spec.Deadline.Time) {
		return protocol.EnrollmentResult{}, issuersigner.PermanentError{Err: fmt.Errorf("CMP transaction exceeded the configured maximum duration of %s", limits.MaximumDuration.Duration)}
	}
	if transaction.Status.Phase != cmpv1alpha1.TransactionPhasePolling {
		// A transaction that never reached the polling phase is retried under its recorded transaction
		// ID, which is how a server recognises a repeated request rather than a new enrollment.
		return s.ProtocolClient.EnrollP10CR(ctx, enrollmentRequest)
	}
	if transaction.Status.CertReqID == nil || len(transaction.Status.RecipNonce) == 0 {
		return protocol.EnrollmentResult{}, issuersigner.PermanentError{Err: fmt.Errorf("recorded CMP transaction is missing the state required to poll")}
	}
	if transaction.Status.Polls >= limits.MaximumPolls {
		return protocol.EnrollmentResult{}, issuersigner.PermanentError{Err: fmt.Errorf("CMP transaction reached the configured maximum of %d polls", limits.MaximumPolls)}
	}
	poll := protocol.PollRequest{Enrollment: enrollmentRequest, RecipNonce: transaction.Status.RecipNonce, CertReqID: *transaction.Status.CertReqID, RequestNonce: transaction.Status.RequestNonce}
	if len(transaction.Status.ResponseSigner) > 0 {
		signer, parseErr := x509.ParseCertificate(transaction.Status.ResponseSigner)
		if parseErr != nil {
			return protocol.EnrollmentResult{}, issuersigner.PermanentError{Err: fmt.Errorf("parse retained CMP response signer: %w", parseErr)}
		}
		poll.ResponseSigner = signer
	}
	return s.ProtocolClient.PollP10CR(ctx, poll)
}

// continuePolling records the state for the next poll and asks the controller to retry after the delay.
// Only a pollReq counts against the poll budget, so the first waiting response does not consume it.
func (s *Signer) continuePolling(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, pending *protocol.PendingTransaction, limits cmpv1alpha1.TransactionSpec, polled bool) error {
	if polled {
		transaction.Status.Polls++
	}
	if err := s.transactions.recordPending(ctx, transaction, pending); err != nil {
		return err
	}
	delay := pollDelay(pending.CheckAfter, limits)
	if deadlineDelay := time.Until(transaction.Spec.Deadline.Time); deadlineDelay > 0 && deadlineDelay < delay {
		delay = deadlineDelay
	}
	log.FromContext(ctx).Info("Waiting for the CMP server to issue the certificate", enrollmentDeadlineValues(transaction, limits, delay)...)
	recordEnrollmentPoll(ctx)
	return issuersigner.PendingError{Err: fmt.Errorf("CMP server has not issued the certificate yet, polling again in %s", delay), RequeueAfter: delay}
}

// failTransaction removes recorded state when a failure ends the transaction and maps the error.
func (s *Signer) failTransaction(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, err error) error {
	mapped := mapProtocolError(err)
	var permanentErr issuersigner.PermanentError
	if errors.As(mapped, &permanentErr) {
		if removeErr := s.transactions.remove(ctx, transaction); removeErr != nil {
			return removeErr
		}
	}
	return mapped
}

// runtimeConfiguration contains locally validated data for one issuer generation.
type runtimeConfiguration struct {
	EndpointScheme    string
	EnrollmentRequest protocol.EnrollmentRequest
	Transaction       cmpv1alpha1.TransactionSpec
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
	var responseCertReqID *int64
	if spec.Protocol.P10CRResponseCertReqID != nil {
		pinned := *spec.Protocol.P10CRResponseCertReqID
		responseCertReqID = &pinned
	}
	request := protocol.EnrollmentRequest{EndpointURL: spec.Endpoint.URL, Timeout: spec.Endpoint.Timeout.Duration, MaxResponseSize: spec.Endpoint.MaxResponseSize, Recipient: recipient, ImplicitConfirm: spec.Protocol.Confirmation == "Implicit", RejectGrantedMods: spec.Policy.GrantedModifications != cmpv1alpha1.GrantedModificationsAccept, ResponseCertReqID: responseCertReqID, Protection: protection, CMPTrust: cmpTrust, TLSRoots: tlsRoots}
	if sender != nil {
		request.Sender = sender
	}
	return runtimeConfiguration{EndpointScheme: parsedEndpoint.Scheme, EnrollmentRequest: request, Transaction: transactionLimitsWithDefaults(spec.Transaction)}, nil
}

// transactionLimitsWithDefaults applies the documented polling defaults to an omitted transaction block.
func transactionLimitsWithDefaults(spec cmpv1alpha1.TransactionSpec) cmpv1alpha1.TransactionSpec {
	if spec.MaximumDuration.Duration <= 0 {
		spec.MaximumDuration = metav1.Duration{Duration: defaultMaximumDuration}
	}
	if spec.MinimumPollInterval.Duration <= 0 {
		spec.MinimumPollInterval = metav1.Duration{Duration: defaultMinimumPollInterval}
	}
	if spec.MaximumPollInterval.Duration < spec.MinimumPollInterval.Duration {
		spec.MaximumPollInterval = metav1.Duration{Duration: defaultMaximumPollInterval}
	}
	if spec.MaximumPolls < 1 {
		spec.MaximumPolls = defaultMaximumPolls
	}
	return spec
}

// pollDelay clamps the server-requested wait into the configured polling bounds.
func pollDelay(checkAfter time.Duration, limits cmpv1alpha1.TransactionSpec) time.Duration {
	if checkAfter < limits.MinimumPollInterval.Duration {
		return limits.MinimumPollInterval.Duration
	}
	if checkAfter > limits.MaximumPollInterval.Duration {
		return limits.MaximumPollInterval.Duration
	}
	return checkAfter
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
	transactionOmitted := transaction.MaximumDuration.Duration == 0 && transaction.MinimumPollInterval.Duration == 0 && transaction.MaximumPollInterval.Duration == 0 && transaction.MaximumPolls == 0
	if !transactionOmitted && (transaction.MaximumDuration.Duration <= 0 || transaction.MinimumPollInterval.Duration <= 0 || transaction.MaximumPollInterval.Duration < transaction.MinimumPollInterval.Duration || transaction.MaximumPolls < 1) {
		return fmt.Errorf("transaction limits are invalid")
	}
	if policy.GrantedModifications != "" && policy.GrantedModifications != cmpv1alpha1.GrantedModificationsReject && policy.GrantedModifications != cmpv1alpha1.GrantedModificationsAccept {
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
		return issuersigner.PendingError{Err: protocolError, RequeueAfter: protocolError.RequeueAfter}
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
