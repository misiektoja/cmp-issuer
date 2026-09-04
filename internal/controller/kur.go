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

// kurMaterial contains the two authorized workload key proofs and their Secret identities.
type kurMaterial struct {
	Protection          protocol.Protection
	RequestedPrivateKey crypto.Signer
	Secrets             map[types.NamespacedName]secretFingerprint
}

// selectedTransactionOperation chooses KUR only for annotated cert-manager renewal revisions.
func selectedTransactionOperation(issuer issuerapi.Issuer, request issuersigner.CertificateRequestObject) (string, error) {
	var spec *cmpv1alpha1.CMPIssuerSpec
	switch typed := issuer.(type) {
	case *cmpv1alpha1.CMPIssuer:
		spec = &typed.Spec
	case *cmpv1alpha1.CMPClusterIssuer:
		spec = &typed.Spec
	default:
		return "", fmt.Errorf("unsupported issuer type %T", issuer)
	}
	if spec.Protocol.Renewal != cmpv1alpha1.RenewalKUR {
		return cmpv1alpha1.TransactionOperationP10CR, nil
	}
	if request.GetAnnotations()[certmanagerv1.CertificateRequestRevisionAnnotationKey] == "" {
		return cmpv1alpha1.TransactionOperationP10CR, nil
	}
	revision, err := certificateRequestRevision(request)
	if err != nil || revision < 1 {
		if err == nil {
			err = fmt.Errorf("certificate revision annotation must be positive")
		}
		return "", fmt.Errorf("select renewal operation: %w", err)
	}
	if revision > 1 {
		return cmpv1alpha1.TransactionOperationKUR, nil
	}
	return cmpv1alpha1.TransactionOperationP10CR, nil
}

// loadKURMaterial authorizes the CertificateRequest owner chain before reading current and staged workload keys.
func (s *Signer) loadKURMaterial(ctx context.Context, request issuersigner.CertificateRequestObject, issuer issuerapi.Issuer, csrDER []byte) (kurMaterial, *configurationError) {
	revision, err := certificateRequestRevision(request)
	if err != nil || revision < 2 {
		if err == nil {
			err = fmt.Errorf("KUR requires a certificate revision greater than one")
		}
		return kurMaterial{}, permanentConfiguration("authorize KUR CertificateRequest", err)
	}
	owner, err := certificateOwnerReference(request)
	if err != nil {
		return kurMaterial{}, permanentConfiguration("authorize KUR CertificateRequest", err)
	}
	certificateKey := types.NamespacedName{Namespace: request.GetNamespace(), Name: owner.Name}
	certificate, configurationErr := s.readOwningCertificate(ctx, certificateKey, owner)
	if configurationErr != nil {
		return kurMaterial{}, configurationErr
	}
	if certificate.Status.Revision == nil || *certificate.Status.Revision != revision-1 {
		return kurMaterial{}, permanentConfiguration("authorize KUR CertificateRequest", fmt.Errorf("CertificateRequest revision does not immediately follow the current Certificate revision"))
	}
	if !certificateIssuerMatches(certificate, issuer) {
		return kurMaterial{}, permanentConfiguration("authorize KUR CertificateRequest", fmt.Errorf("owning Certificate refers to a different issuer"))
	}
	annotations := request.GetAnnotations()
	stagedName := annotations[certmanagerv1.CertificateRequestPrivateKeyAnnotationKey]
	if stagedName == "" || certificate.Status.NextPrivateKeySecretName == nil || stagedName != *certificate.Status.NextPrivateKeySecretName {
		return kurMaterial{}, permanentConfiguration("authorize KUR staged private key", fmt.Errorf("CertificateRequest private-key annotation does not match Certificate status.nextPrivateKeySecretName"))
	}
	if certificate.Spec.SecretName == "" || certificate.Spec.SecretName == stagedName {
		return kurMaterial{}, permanentConfiguration("authorize KUR current certificate", fmt.Errorf("certificate current and staged Secret names must be distinct"))
	}
	currentKey := types.NamespacedName{Namespace: request.GetNamespace(), Name: certificate.Spec.SecretName}
	currentSecret, configurationErr := s.readKURSecret(ctx, currentKey, "current certificate Secret")
	if configurationErr != nil {
		return kurMaterial{}, configurationErr
	}
	stagedKey := types.NamespacedName{Namespace: request.GetNamespace(), Name: stagedName}
	stagedSecret, configurationErr := s.readKURSecret(ctx, stagedKey, "staged private-key Secret")
	if configurationErr != nil {
		return kurMaterial{}, configurationErr
	}
	if !secretControlledByCertificate(stagedSecret, certificate) || stagedSecret.Labels[certmanagerv1.IsNextPrivateKeySecretLabelKey] != "true" {
		return kurMaterial{}, permanentConfiguration("authorize KUR staged private key", fmt.Errorf("staged private-key Secret is not the cert-manager-owned next key for the Certificate"))
	}
	certificates, err := protocol.ParseCertificates(currentSecret.Data[corev1.TLSCertKey])
	if err != nil || len(certificates) == 0 {
		if err == nil {
			err = fmt.Errorf("current certificate Secret contains no certificate")
		}
		return kurMaterial{}, retryableConfiguration("parse KUR current certificate", err)
	}
	oldKey, err := parseSecretSigner(currentSecret, corev1.TLSPrivateKeyKey)
	if err != nil {
		return kurMaterial{}, retryableConfiguration("parse KUR current private key", err)
	}
	if err := protocol.ValidateSignerCertificate(oldKey, certificates[0]); err != nil {
		return kurMaterial{}, permanentConfiguration("validate KUR current key pair", err)
	}
	requestedKey, err := parseSecretSigner(stagedSecret, corev1.TLSPrivateKeyKey)
	if err != nil {
		return kurMaterial{}, retryableConfiguration("parse KUR staged private key", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || !protocol.PublicKeysEqual(requestedKey.Public(), csr.PublicKey) {
		if err == nil {
			err = fmt.Errorf("staged private key does not match the CertificateRequest CSR")
		}
		return kurMaterial{}, permanentConfiguration("validate KUR staged private key", err)
	}
	secrets := map[types.NamespacedName]secretFingerprint{currentKey: workloadSecretFingerprint(currentSecret, corev1.TLSCertKey, corev1.TLSPrivateKeyKey), stagedKey: workloadSecretFingerprint(stagedSecret, corev1.TLSPrivateKeyKey)}
	return kurMaterial{Protection: protocol.Protection{Signature: &protocol.SignatureProtection{PrivateKey: oldKey, Certificate: certificates[0], Chain: certificates[1:]}}, RequestedPrivateKey: requestedKey, Secrets: secrets}, nil
}

// readOwningCertificate reads the controlling Certificate and confirms it is the recorded live owner.
func (s *Signer) readOwningCertificate(ctx context.Context, key types.NamespacedName, owner metav1.OwnerReference) (*certmanagerv1.Certificate, *configurationError) {
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
		return nil, permanentConfiguration("authorize KUR CertificateRequest", fmt.Errorf("certificate owner identity is absent, deleted or mismatched"))
	}
	return certificate, nil
}

// workloadSecretFingerprint identifies a workload Secret by its UID and the data keys KUR consumes,
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
	if owner == nil || owner.APIVersion != certmanagerv1.SchemeGroupVersion.String() || owner.Kind != "Certificate" || owner.Name == "" || owner.UID == "" {
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

// readKURSecret reads one exact workload Secret and treats cert-manager creation races as retryable.
func (s *Signer) readKURSecret(ctx context.Context, key types.NamespacedName, description string) (*corev1.Secret, *configurationError) {
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
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == certmanagerv1.SchemeGroupVersion.String() && owner.Kind == "Certificate" && owner.Name == certificate.Name && owner.UID == certificate.UID {
			return true
		}
	}
	return false
}

// parseSecretSigner reads one non-empty Secret key as an unencrypted signing key.
func parseSecretSigner(secret *corev1.Secret, key string) (crypto.Signer, error) {
	data, found := secret.Data[key]
	if !found || len(data) == 0 {
		return nil, fmt.Errorf("required key %q is absent or empty", key)
	}
	return protocol.ParseSigner(data)
}
