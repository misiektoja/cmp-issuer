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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	pemCertificateBlockType = "CERTIFICATE"
	schemeHTTP              = "http"
	schemeHTTPS             = "https"
	// The polling defaults match the CRD defaults and apply when the transaction block is omitted.
	defaultMaximumDuration     = 10 * time.Minute
	defaultMinimumPollInterval = time.Second
	defaultMaximumPollInterval = 5 * time.Minute
	defaultMaximumPolls        = 60
	// Enrollment starts with CMPv2, while certificate confirmation may require CMPv3.
	cmpProtocolVersion = 2
)

// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmpissuers;cmpclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmpissuers/status;cmpclusterissuers/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmptransactions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certmanager.misiektoja.github.io,resources=cmptransactions/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Signer loads issuer credentials and delegates protected transactions to a project-owned client.
type Signer struct {
	KubeClient               client.Reader
	ProtocolClient           protocol.Client
	EventRecorder            events.EventRecorder
	ClusterResourceNamespace string
	WatchNamespace           string
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
	if s.ClusterResourceNamespace == "" && s.WatchNamespace == "" {
		return fmt.Errorf("cluster resource namespace is required")
	}
	if s.transactions == nil {
		s.transactions = &transactionStore{reader: manager.GetAPIReader(), writer: manager.GetClient()}
	}
	combined := &controllers.CombinedController{
		IssuerTypes:                    []issuerapi.Issuer{&cmpv1alpha1.CMPIssuer{}},
		FieldOwner:                     fieldOwner,
		MaxRetryDuration:               2 * time.Minute,
		Check:                          s.Check,
		Sign:                           s.Sign,
		EventRecorder:                  s.EventRecorder,
		SetCAOnCertificateRequest:      false,
		DisableKubernetesCSRController: true,
	}
	if s.WatchNamespace == "" {
		combined.ClusterIssuerTypes = []issuerapi.Issuer{&cmpv1alpha1.CMPClusterIssuer{}}
	}
	return combined.SetupWithManager(ctx, manager)
}

// Check validates issuer configuration and credentials without contacting the CMP server.
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
	details, err := request.GetCertificateDetails()
	if err != nil {
		return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: fmt.Errorf("read CertificateRequest details: %w", err)}
	}
	requestDER, err := protocol.ParseCertificateRequestDER(details.CSR)
	if err != nil {
		return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: err}
	}
	csrDigest := csrDigestHex(requestDER)
	operation, err := selectedTransactionOperation(issuer, request)
	if err != nil {
		return issuersigner.PEMBundle{}, issuersigner.PermanentError{Err: err}
	}
	transaction, err := s.transactions.load(ctx, request.GetNamespace(), request.GetName(), request.GetUID())
	if err != nil {
		return issuersigner.PEMBundle{}, err
	}
	resumed := transaction != nil
	if resumed {
		logResumedTransaction(ctx, transaction)
		expectedIssuer := issuerReference(issuer)
		if validationErr := validateResumedTransaction(transaction, csrDigest, operation, expectedIssuer); validationErr != nil {
			return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, issuersigner.PermanentError{Err: validationErr})
		}
		// The transaction outlives this reconcile, so issuance is timed from the record that started it.
		enrollmentStarted = transactionStartTime(transaction, enrollmentStarted)
		if transaction.Status.Phase == cmpv1alpha1.TransactionPhaseIssued {
			return recoverIssuedChain(ctx, transaction, requestDER)
		}
		if transaction.Spec.IssuerRef.Generation != expectedIssuer.Generation {
			return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, issuersigner.PermanentError{Err: fmt.Errorf("issuer spec changed during the recorded CMP transaction")})
		}
	}
	runtimeConfiguration, configurationErr := s.loadRuntimeConfiguration(ctx, issuer)
	if configurationErr != nil {
		return issuersigner.PEMBundle{}, issuersigner.IssuerError{Err: configurationErr}
	}
	enrollmentRequest := runtimeConfiguration.EnrollmentRequest
	enrollmentRequest.CSRDER = requestDER
	enrollmentRequest.Operation = operation
	if operation == cmpv1alpha1.TransactionOperationKUR && runtimeConfiguration.RenewalEndpointURL != "" {
		enrollmentRequest.EndpointURL = runtimeConfiguration.RenewalEndpointURL
	}
	ctx = log.IntoContext(ctx, log.FromContext(ctx).WithValues("endpoint", logging.Text(enrollmentRequest.EndpointURL)))
	if operation == cmpv1alpha1.TransactionOperationKUR {
		if preparationErr := s.prepareKUREnrollment(ctx, request, issuer, requestDER, &runtimeConfiguration, &enrollmentRequest); preparationErr != nil {
			return issuersigner.PEMBundle{}, preparationErr
		}
	}
	limits := runtimeConfiguration.Transaction
	if !resumed {
		// The transaction is recorded before the first message is sent, so that a controller restart
		// resumes this transaction instead of starting a second enrollment for the same request.
		transaction, err = s.transactions.create(ctx, request.GetNamespace(), request.GetName(), request.GetUID(), time.Now().Add(limits.MaximumDuration.Duration), transactionDetail{
			CSRDigest:           csrDigest,
			IssuerRef:           issuerReference(issuer),
			ConfigurationDigest: runtimeConfiguration.ConfigurationDigest,
			Operation:           operation,
			ProtocolVersion:     cmpProtocolVersion,
		})
		if err != nil {
			return issuersigner.PEMBundle{}, err
		}
	}
	if resumed {
		if transaction.Spec.ConfigurationDigest == "" || transaction.Spec.ConfigurationDigest != runtimeConfiguration.ConfigurationDigest {
			return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, issuersigner.PermanentError{Err: fmt.Errorf("issuer credentials changed during the recorded CMP transaction")})
		}
	} else {
		log.FromContext(ctx).V(1).Info("Recorded CMP transaction before sending the first message", "operation", enrollmentLogValue(transaction), "deadline", timestampLogValue(transaction.Spec.Deadline.Time))
	}
	ctx = log.IntoContext(ctx, log.FromContext(ctx).WithValues("transactionID", transactionIDLogValue(transaction.Spec.TransactionID)))
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

// validateResumedTransaction binds a recorded transaction to the same request, operation and issuer identity.
func validateResumedTransaction(transaction *cmpv1alpha1.CMPTransaction, csrDigest string, operation string, expectedIssuer cmpv1alpha1.TransactionIssuerReference) error {
	if transaction.Spec.CSRDigest != "" && transaction.Spec.CSRDigest != csrDigest {
		return fmt.Errorf("recorded CMP transaction enrolls a different certificate signing request")
	}
	if transaction.Spec.IssuerRef == nil || transaction.Spec.IssuerRef.Name != expectedIssuer.Name || transaction.Spec.IssuerRef.Kind != expectedIssuer.Kind || transaction.Spec.IssuerRef.UID != expectedIssuer.UID {
		return fmt.Errorf("recorded CMP transaction belongs to a different issuer identity")
	}
	if transaction.Spec.Operation != "" && transaction.Spec.Operation != operation {
		return fmt.Errorf("recorded CMP transaction uses a different enrollment operation")
	}
	return nil
}

// transactionStartTime returns the persisted start time when a transaction outlives one reconcile.
func transactionStartTime(transaction *cmpv1alpha1.CMPTransaction, fallback time.Time) time.Time {
	if transaction.CreationTimestamp.IsZero() {
		return fallback
	}
	return transaction.CreationTimestamp.Time
}

// prepareKUREnrollment authorizes workload keys and binds them to the runtime request and configuration digest.
func (s *Signer) prepareKUREnrollment(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer, requestDER []byte, runtimeConfiguration *runtimeConfiguration, enrollmentRequest *protocol.EnrollmentRequest) error {
	material, materialErr := s.loadKURMaterial(ctx, request, issuer, requestDER)
	if materialErr != nil {
		if materialErr.Permanent {
			return issuersigner.PermanentError{Err: materialErr}
		}
		return issuersigner.PendingError{Err: materialErr, RequeueAfter: time.Second}
	}
	enrollmentRequest.Protection = material.Protection
	enrollmentRequest.RequestedPrivateKey = material.RequestedPrivateKey
	enrollmentRequest.ResponseCertReqID = nil
	maps.Copy(runtimeConfiguration.ConfigurationSecrets, material.Secrets)
	configurationDigest, err := runtimeConfigurationDigest(issuerReference(issuer), runtimeConfiguration.ConfigurationSecrets)
	if err != nil {
		return issuersigner.PermanentError{Err: fmt.Errorf("identify KUR configuration: %w", err)}
	}
	runtimeConfiguration.ConfigurationDigest = configurationDigest
	if err := protocol.ValidateKURRequest(*enrollmentRequest); err != nil {
		return mapProtocolError(err)
	}
	return nil
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
	confirmRequest := protocol.ConfirmRequest{
		Enrollment:     enrollmentRequest,
		Certificate:    chain[0],
		CertReqID:      pending.CertReqID,
		RecipNonce:     pending.RecipNonce,
		ResponseSigner: pending.ResponseSigner,
		RequestNonce:   pending.RequestNonce,
	}
	result, err := s.ProtocolClient.ConfirmP10CR(ctx, confirmRequest)
	if err != nil {
		return issuersigner.PEMBundle{}, s.failTransaction(ctx, transaction, err)
	}
	if result.PendingConfirmation != nil {
		return issuersigner.PEMBundle{}, s.continueConfirming(ctx, transaction, chain, result.PendingConfirmation, limits, len(pending.RequestNonce) > 0)
	}
	if err := s.transactions.recordIssued(ctx, transaction, chain); err != nil {
		return issuersigner.PEMBundle{}, err
	}
	logIssuedCertificate(ctx, transaction, chain, confirmationExplicit, enrollmentStarted)
	recordIssuedEnrollment(ctx, confirmationExplicit, enrollmentStarted)
	return issuersigner.PEMBundle{ChainPEM: encodeChainPEM(chain)}, nil
}

// continueConfirming records the state for the next confirmation poll and asks for a later retry.
func (s *Signer) continueConfirming(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, chain []*x509.Certificate, pending *protocol.PendingTransaction, limits cmpv1alpha1.TransactionSpec, polled bool) error {
	if polled {
		transaction.Status.Polls++
	}
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
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: pemCertificateBlockType, Bytes: certificate.Raw})...)
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
	return cmpv1alpha1.TransactionIssuerReference{Name: issuer.GetName(), Kind: kind, UID: string(issuer.GetUID()), Generation: issuer.GetGeneration()}
}

// exchange sends the enrollment request, or resumes a transaction the server answered with waiting.
func (s *Signer) exchange(ctx context.Context, enrollmentRequest protocol.EnrollmentRequest, transaction *cmpv1alpha1.CMPTransaction, limits cmpv1alpha1.TransactionSpec) (protocol.EnrollmentResult, error) {
	if time.Now().After(transaction.Spec.Deadline.Time) {
		return protocol.EnrollmentResult{}, issuersigner.PermanentError{Err: fmt.Errorf("CMP transaction exceeded the configured maximum duration of %s", limits.MaximumDuration.Duration)}
	}
	if transaction.Status.Phase != cmpv1alpha1.TransactionPhasePolling {
		// A transaction that never reached the polling phase is retried under its recorded transaction
		// ID, which is how a server recognises a repeated request rather than a new enrollment.
		if transaction.Spec.Operation == cmpv1alpha1.TransactionOperationKUR {
			return s.ProtocolClient.EnrollKUR(ctx, enrollmentRequest)
		}
		return s.ProtocolClient.EnrollP10CR(ctx, enrollmentRequest)
	}
	if transaction.Status.CertReqID == nil || len(transaction.Status.RecipNonce) == 0 {
		return protocol.EnrollmentResult{}, issuersigner.PermanentError{Err: fmt.Errorf("recorded CMP transaction is missing the state required to poll")}
	}
	if transaction.Status.Polls >= limits.MaximumPolls {
		return protocol.EnrollmentResult{}, issuersigner.PermanentError{Err: fmt.Errorf("CMP transaction reached the configured maximum of %d polls", limits.MaximumPolls)}
	}
	poll := protocol.PollRequest{
		Enrollment:   enrollmentRequest,
		RecipNonce:   transaction.Status.RecipNonce,
		CertReqID:    *transaction.Status.CertReqID,
		RequestNonce: transaction.Status.RequestNonce,
	}
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
		return issuersigner.PendingError{Err: protocolError, RequeueAfter: time.Second}
	default:
		return issuersigner.PermanentError{Err: fmt.Errorf("unknown protocol error classification: %w", protocolError)}
	}
}
