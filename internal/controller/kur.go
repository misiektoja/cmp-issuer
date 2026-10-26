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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// certificateKind is the cert-manager owner kind that authorizes an IR or KUR.
const certificateKind = "Certificate"

// workloadKeyMaterial contains the authorized workload key proofs of an IR or KUR and their Secret
// identities. Protection is set only for KUR, whose current certificate protects the message.
type workloadKeyMaterial struct {
	Protection          *protocol.Protection
	RequestedPrivateKey crypto.Signer
	Secrets             map[types.NamespacedName]secretFingerprint
}

// selectedTransactionOperation chooses the initial enrollment operation for the first cert-manager
// revision and the renewal operation for later ones.
func selectedTransactionOperation(issuer issuerapi.Issuer, request issuersigner.CertificateRequestObject) (string, error) {
	spec, err := cmpIssuerSpec(issuer)
	if err != nil {
		return "", err
	}
	initial := initialOperation(spec.Protocol)
	renewal := renewalOperation(spec.Protocol)
	if initial == cmpv1alpha1.TransactionOperationP10CR && renewal == cmpv1alpha1.TransactionOperationP10CR {
		return cmpv1alpha1.TransactionOperationP10CR, nil
	}
	if request.GetAnnotations()[certmanagerv1.CertificateRequestRevisionAnnotationKey] == "" {
		// A CertificateRequest created without a Certificate has no staged key cmp-issuer may read,
		// so it can be enrolled by P10CR only.
		if initial == cmpv1alpha1.TransactionOperationIR {
			return "", fmt.Errorf("select enrollment operation: IR needs a CertificateRequest that cert-manager created for a Certificate, because the Certificate's staged private key signs the proof of possession")
		}
		return cmpv1alpha1.TransactionOperationP10CR, nil
	}
	revision, err := certificateRequestRevision(request)
	if err != nil || revision < 1 {
		if err == nil {
			err = fmt.Errorf("certificate revision annotation must be positive")
		}
		return "", fmt.Errorf("select enrollment operation: %w", err)
	}
	if revision > 1 {
		return renewal, nil
	}
	return initial, nil
}

// cmpIssuerSpec returns the spec of a CMPIssuer or CMPClusterIssuer.
func cmpIssuerSpec(issuer issuerapi.Issuer) (*cmpv1alpha1.CMPIssuerSpec, error) {
	switch typed := issuer.(type) {
	case *cmpv1alpha1.CMPIssuer:
		return &typed.Spec, nil
	case *cmpv1alpha1.CMPClusterIssuer:
		return &typed.Spec, nil
	default:
		return nil, fmt.Errorf("unsupported issuer type %T", issuer)
	}
}

// initialOperation returns the configured initial enrollment operation.
func initialOperation(protocolSpec cmpv1alpha1.ProtocolSpec) string {
	if protocolSpec.InitialEnrollment == cmpv1alpha1.InitialEnrollmentIR {
		return cmpv1alpha1.TransactionOperationIR
	}
	return cmpv1alpha1.TransactionOperationP10CR
}

// renewalOperation returns the configured renewal operation, which follows initialEnrollment when
// omitted: P10CR after P10CR and KUR after IR.
func renewalOperation(protocolSpec cmpv1alpha1.ProtocolSpec) string {
	switch protocolSpec.Renewal {
	case cmpv1alpha1.RenewalKUR:
		return cmpv1alpha1.TransactionOperationKUR
	case cmpv1alpha1.RenewalP10CR:
		return cmpv1alpha1.TransactionOperationP10CR
	}
	if protocolSpec.InitialEnrollment == cmpv1alpha1.InitialEnrollmentIR {
		return cmpv1alpha1.TransactionOperationKUR
	}
	return cmpv1alpha1.TransactionOperationP10CR
}

// loadIRMaterial authorizes the CertificateRequest owner chain before reading the staged workload key.
// IR serves the first revision. A later revision is authorized only when the issuer falls back from
// KUR to IR and the caller passes a renewal fallback reason from its own classification of the current
// certificate or from the recorded transaction.
func (s *Signer) loadIRMaterial(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer, csrDER []byte, renewalFallbackReason string) (workloadKeyMaterial, *configurationError) {
	renewal := renewalFallbackReason != ""
	if renewal && renewalFallbackOperation(issuer) != cmpv1alpha1.TransactionOperationIR {
		return workloadKeyMaterial{}, permanentConfiguration("authorize IR CertificateRequest", fmt.Errorf("issuer does not fall back from KUR to IR"))
	}
	certificate, configurationErr := s.authorizeOwningCertificate(ctx, request, issuer, cmpv1alpha1.TransactionOperationIR, renewal)
	if configurationErr != nil {
		return workloadKeyMaterial{}, configurationErr
	}
	stagedName, configurationErr := authorizedStagedKeyName(request, certificate, cmpv1alpha1.TransactionOperationIR)
	if configurationErr != nil {
		return workloadKeyMaterial{}, configurationErr
	}
	stagedKey := types.NamespacedName{Namespace: request.GetNamespace(), Name: stagedName}
	stagedSecret, requestedKey, configurationErr := s.loadStagedKey(ctx, stagedKey, certificate, csrDER, cmpv1alpha1.TransactionOperationIR)
	if configurationErr != nil {
		return workloadKeyMaterial{}, configurationErr
	}
	secrets := map[types.NamespacedName]secretFingerprint{stagedKey: workloadSecretFingerprint(stagedSecret, corev1.TLSPrivateKeyKey)}
	return workloadKeyMaterial{RequestedPrivateKey: requestedKey, Secrets: secrets}, nil
}

// loadKURMaterial authorizes the CertificateRequest owner chain before reading current and staged workload keys.
func (s *Signer) loadKURMaterial(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer, csrDER []byte) (workloadKeyMaterial, *configurationError) {
	certificate, configurationErr := s.authorizeOwningCertificate(ctx, request, issuer, cmpv1alpha1.TransactionOperationKUR, true)
	if configurationErr != nil {
		return workloadKeyMaterial{}, configurationErr
	}
	stagedName, configurationErr := authorizedStagedKeyName(request, certificate, cmpv1alpha1.TransactionOperationKUR)
	if configurationErr != nil {
		return workloadKeyMaterial{}, configurationErr
	}
	if certificate.Spec.SecretName == "" || certificate.Spec.SecretName == stagedName {
		return workloadKeyMaterial{}, permanentConfiguration("authorize KUR current certificate", fmt.Errorf("certificate current and staged Secret names must be distinct"))
	}
	currentKey := types.NamespacedName{Namespace: request.GetNamespace(), Name: certificate.Spec.SecretName}
	currentSecret, configurationErr := s.readCurrentSecret(ctx, currentKey)
	if configurationErr != nil {
		return workloadKeyMaterial{}, configurationErr
	}
	if currentSecret == nil {
		return workloadKeyMaterial{}, permanentConfiguration("read current certificate Secret", currentCertificateUnavailable(currentKey.Name, "does not exist"))
	}
	if err := currentSecretIssuedForCertificate(currentSecret, certificate); err != nil {
		return workloadKeyMaterial{}, permanentConfiguration("authorize KUR current certificate", err)
	}
	stagedKey := types.NamespacedName{Namespace: request.GetNamespace(), Name: stagedName}
	stagedSecret, requestedKey, configurationErr := s.loadStagedKey(ctx, stagedKey, certificate, csrDER, cmpv1alpha1.TransactionOperationKUR)
	if configurationErr != nil {
		return workloadKeyMaterial{}, configurationErr
	}
	if len(currentSecret.Data[corev1.TLSCertKey]) == 0 {
		return workloadKeyMaterial{}, permanentConfiguration("parse KUR current certificate", currentCertificateUnavailable(currentKey.Name, "holds no certificate"))
	}
	certificates, err := protocol.ParseCertificates(currentSecret.Data[corev1.TLSCertKey])
	if err != nil || len(certificates) == 0 {
		if err == nil {
			err = fmt.Errorf("current certificate Secret contains no certificate")
		}
		return workloadKeyMaterial{}, retryableConfiguration("parse KUR current certificate", err)
	}
	oldKey, err := parseSecretSigner(currentSecret, corev1.TLSPrivateKeyKey)
	if err != nil {
		return workloadKeyMaterial{}, retryableConfiguration("parse KUR current private key", err)
	}
	if err := protocol.ValidateSignerCertificate(oldKey, certificates[0]); err != nil {
		return workloadKeyMaterial{}, permanentConfiguration("validate KUR current key pair", err)
	}
	secrets := map[types.NamespacedName]secretFingerprint{currentKey: workloadSecretFingerprint(currentSecret, corev1.TLSCertKey, corev1.TLSPrivateKeyKey), stagedKey: workloadSecretFingerprint(stagedSecret, corev1.TLSPrivateKeyKey)}
	protection := &protocol.Protection{Signature: &protocol.SignatureProtection{PrivateKey: oldKey, Certificate: certificates[0], Chain: certificates[1:]}}
	return workloadKeyMaterial{Protection: protection, RequestedPrivateKey: requestedKey, Secrets: secrets}, nil
}

// authorizeOwningCertificate returns the live controlling Certificate of an IR or KUR request after
// checking that the request is its next revision and that it names the issuer serving the request.
// A renewal, which is every KUR and an IR that falls back from KUR, serves a revision greater than
// one. An initial enrollment serves the first revision.
func (s *Signer) authorizeOwningCertificate(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer, operation string, renewal bool) (*certmanagerv1.Certificate, *configurationError) {
	authorization := "authorize " + operation + " CertificateRequest"
	revision, err := certificateRequestRevision(request)
	if err == nil && !renewal && revision != 1 {
		err = fmt.Errorf("%s requires the first certificate revision", operation)
	}
	if err == nil && renewal && revision < 2 {
		err = fmt.Errorf("%s renewal requires a certificate revision greater than one", operation)
	}
	if err != nil {
		return nil, permanentConfiguration(authorization, err)
	}
	owner, err := certificateOwnerReference(request)
	if err != nil {
		return nil, permanentConfiguration(authorization, err)
	}
	certificateKey := types.NamespacedName{Namespace: request.GetNamespace(), Name: owner.Name}
	certificate, configurationErr := s.readOwningCertificate(ctx, certificateKey, owner, operation)
	if configurationErr != nil {
		return nil, configurationErr
	}
	// cert-manager leaves status.revision unset until the first certificate is issued.
	previous := 0
	if certificate.Status.Revision != nil {
		previous = *certificate.Status.Revision
	}
	if previous != revision-1 {
		return nil, permanentConfiguration(authorization, fmt.Errorf("CertificateRequest revision does not immediately follow the current Certificate revision"))
	}
	if !certificateIssuerMatches(certificate, issuer) {
		return nil, permanentConfiguration(authorization, fmt.Errorf("owning Certificate refers to a different issuer"))
	}
	return certificate, nil
}

// authorizedStagedKeyName returns the staged private-key Secret name of a request once it matches
// the name the owning Certificate records, so the annotation alone never selects a Secret to read.
func authorizedStagedKeyName(request issuersigner.CertificateRequestObject, certificate *certmanagerv1.Certificate, operation string) (string, *configurationError) {
	stagedName := request.GetAnnotations()[certmanagerv1.CertificateRequestPrivateKeyAnnotationKey]
	if stagedName == "" || certificate.Status.NextPrivateKeySecretName == nil || stagedName != *certificate.Status.NextPrivateKeySecretName {
		return "", permanentConfiguration("authorize "+operation+" staged private key", fmt.Errorf("CertificateRequest private-key annotation does not match Certificate status.nextPrivateKeySecretName"))
	}
	return stagedName, nil
}

// loadStagedKey reads the staged private key cert-manager generated for the Certificate's next
// revision and checks that it is the key of the CSR.
func (s *Signer) loadStagedKey(ctx context.Context, key types.NamespacedName, certificate *certmanagerv1.Certificate, csrDER []byte, operation string) (*corev1.Secret, crypto.Signer, *configurationError) {
	stagedSecret, configurationErr := s.readWorkloadSecret(ctx, key, "staged private-key Secret")
	if configurationErr != nil {
		return nil, nil, configurationErr
	}
	if !secretControlledByCertificate(stagedSecret, certificate) || stagedSecret.Labels[certmanagerv1.IsNextPrivateKeySecretLabelKey] != "true" {
		return nil, nil, permanentConfiguration("authorize "+operation+" staged private key", fmt.Errorf("staged private-key Secret is not the cert-manager-owned next key for the Certificate"))
	}
	requestedKey, err := parseSecretSigner(stagedSecret, corev1.TLSPrivateKeyKey)
	if err != nil {
		return nil, nil, retryableConfiguration("parse "+operation+" staged private key", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || !protocol.PublicKeysEqual(requestedKey.Public(), csr.PublicKey) {
		if err == nil {
			err = fmt.Errorf("staged private key does not match the CertificateRequest CSR")
		}
		return nil, nil, permanentConfiguration("validate "+operation+" staged private key", err)
	}
	return stagedSecret, requestedKey, nil
}

// readOwningCertificate reads the controlling Certificate and confirms it is the recorded live owner.
func (s *Signer) readOwningCertificate(ctx context.Context, key types.NamespacedName, owner metav1.OwnerReference, operation string) (*certmanagerv1.Certificate, *configurationError) {
	certificate := &certmanagerv1.Certificate{}
	if err := s.KubeClient.Get(ctx, key, certificate); err != nil {
		// Only an absent owner is final, because the recorded owner UID cannot return. Any other
		// failure is API-server state that a later reconcile can succeed against.
		if apierrors.IsNotFound(err) {
			return nil, permanentConfiguration("read owning Certificate", err)
		}
		return nil, retryableConfiguration("read owning Certificate", err)
	}
	if certificate.UID == "" || owner.UID != certificate.UID || certificate.DeletionTimestamp != nil {
		return nil, permanentConfiguration("authorize "+operation+" CertificateRequest", fmt.Errorf("certificate owner identity is absent, deleted or mismatched"))
	}
	return certificate, nil
}

// workloadSecretFingerprint identifies a workload Secret by its UID and the data keys IR or KUR consumes,
// so a metadata-only write to the Secret leaves an unfinished transaction valid while a change to
// the key material still stops it.
func workloadSecretFingerprint(secret *corev1.Secret, keys ...string) secretFingerprint {
	digest := sha256.New()
	for _, key := range keys {
		digest.Write([]byte(key))
		digest.Write([]byte{0})
		value := sha256.Sum256(secret.Data[key])
		digest.Write(value[:])
	}
	return secretFingerprint{UID: string(secret.UID), DataDigest: hex.EncodeToString(digest.Sum(nil))}
}

// certificateRequestRevision parses cert-manager's immutable revision annotation.
func certificateRequestRevision(request issuersigner.CertificateRequestObject) (int, error) {
	value := request.GetAnnotations()[certmanagerv1.CertificateRequestRevisionAnnotationKey]
	revision, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("certificate revision annotation is absent or invalid")
	}
	return revision, nil
}

// certificateOwnerReference returns the single controlling cert-manager Certificate owner.
func certificateOwnerReference(request issuersigner.CertificateRequestObject) (metav1.OwnerReference, error) {
	var owner *metav1.OwnerReference
	owners := request.GetOwnerReferences()
	for index := range owners {
		candidate := &owners[index]
		if candidate.Controller == nil || !*candidate.Controller {
			continue
		}
		if owner != nil {
			return metav1.OwnerReference{}, fmt.Errorf("CertificateRequest has more than one controlling owner")
		}
		owner = candidate
	}
	if owner == nil || owner.APIVersion != certmanagerv1.SchemeGroupVersion.String() || owner.Kind != certificateKind || owner.Name == "" || owner.UID == "" {
		return metav1.OwnerReference{}, fmt.Errorf("CertificateRequest is not controlled by a cert-manager.io/v1 Certificate")
	}
	return *owner, nil
}

// certificateIssuerMatches binds the owning Certificate to the issuer serving this request.
func certificateIssuerMatches(certificate *certmanagerv1.Certificate, issuer issuerapi.Issuer) bool {
	expectedKind := cmpv1alpha1.TransactionIssuerKindNamespaced
	if _, clusterScoped := issuer.(*cmpv1alpha1.CMPClusterIssuer); clusterScoped {
		expectedKind = cmpv1alpha1.TransactionIssuerKindCluster
	}
	reference := certificate.Spec.IssuerRef
	return reference.Name == issuer.GetName() && reference.Group == cmpv1alpha1.GroupVersion.Group && reference.Kind == expectedKind
}

// readWorkloadSecret reads one exact workload Secret and treats cert-manager creation races as retryable.
func (s *Signer) readWorkloadSecret(ctx context.Context, key types.NamespacedName, description string) (*corev1.Secret, *configurationError) {
	secret := &corev1.Secret{}
	if err := s.KubeClient.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, retryableConfiguration("read "+description, fmt.Errorf("secret %q is not available", key.Name))
		}
		return nil, retryableConfiguration("read "+description, err)
	}
	return secret, nil
}

// secretControlledByCertificate verifies the exact controller owner name and UID on a staged key Secret.
func secretControlledByCertificate(secret *corev1.Secret, certificate *certmanagerv1.Certificate) bool {
	for _, owner := range secret.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == certmanagerv1.SchemeGroupVersion.String() && owner.Kind == certificateKind && owner.Name == certificate.Name && owner.UID == certificate.UID {
			return true
		}
	}
	return false
}

// currentSecretIssuedForCertificate verifies cert-manager wrote the current output Secret for the
// owning Certificate. The annotation carries the binding because cert-manager adds a controller owner
// reference to an output Secret only when it runs with --enable-certificate-owner-ref, so a reference
// is checked whenever one is present.
func currentSecretIssuedForCertificate(secret *corev1.Secret, certificate *certmanagerv1.Certificate) error {
	name, annotated := secret.Annotations[certmanagerv1.CertificateNameKey]
	if !annotated {
		return fmt.Errorf("current certificate Secret carries no %s annotation, so cert-manager did not write it for this Certificate", certmanagerv1.CertificateNameKey)
	}
	if name != certificate.Name {
		return fmt.Errorf("current certificate Secret was written for Certificate %q", name)
	}
	for _, owner := range secret.OwnerReferences {
		if owner.Controller == nil || !*owner.Controller {
			continue
		}
		if owner.APIVersion != certmanagerv1.SchemeGroupVersion.String() || owner.Kind != certificateKind || owner.Name != certificate.Name || owner.UID != certificate.UID {
			return fmt.Errorf("current certificate Secret is controlled by another resource")
		}
	}
	return nil
}

// parseSecretSigner reads one non-empty Secret key as an unencrypted signing key.
func parseSecretSigner(secret *corev1.Secret, key string) (crypto.Signer, error) {
	data, found := secret.Data[key]
	if !found || len(data) == 0 {
		return nil, fmt.Errorf("required key %q is absent or empty", key)
	}
	return protocol.ParseSigner(data)
}
