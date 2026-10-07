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
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

// runtimeConfiguration contains locally validated data for one issuer generation.
type runtimeConfiguration struct {
	EndpointScheme       string
	RenewalEndpointURL   string
	EnrollmentRequest    protocol.EnrollmentRequest
	Transaction          cmpv1alpha1.TransactionSpec
	ConfigurationDigest  string
	ConfigurationSecrets map[types.NamespacedName]secretFingerprint
}

// secretFingerprint identifies the version of one Secret a transaction depends on. A credential
// Secret carries its resourceVersion, because any write to it is a rotation signal. A KUR workload
// Secret carries a digest of the key material actually consumed instead, so a metadata-only write by
// another controller does not fail an unfinished transaction.
type secretFingerprint struct {
	UID             string
	ResourceVersion string
	DataDigest      string
}

// credentialFingerprints identifies credential Secrets by their UID and resourceVersion.
func credentialFingerprints(secrets map[types.NamespacedName]*corev1.Secret) map[types.NamespacedName]secretFingerprint {
	fingerprints := make(map[types.NamespacedName]secretFingerprint, len(secrets))
	for key, secret := range secrets {
		fingerprints[key] = secretFingerprint{UID: string(secret.UID), ResourceVersion: secret.ResourceVersion}
	}
	return fingerprints
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
	secrets := map[types.NamespacedName]*corev1.Secret{}
	getSecret := func(reference cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError) {
		key := types.NamespacedName{Namespace: namespace, Name: reference.Name}
		if secret, found := secrets[key]; found {
			return secret, nil
		}
		secret := &corev1.Secret{}
		if err := s.KubeClient.Get(ctx, key, secret); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, retryableConfiguration("read credential Secret", fmt.Errorf("referenced Secret %q is not available", reference.Name))
			}
			return nil, retryableConfiguration("read credential Secret", err)
		}
		secrets[key] = secret
		return secret, nil
	}
	cmpTrust, cmpTrustCertificates, configurationErr := loadTrustPool(getSecret, spec.CMPTrust.CASecretRef)
	if configurationErr != nil {
		return runtimeConfiguration{}, configurationErr
	}
	responseCertificates, configurationErr := loadResponseCertificates(getSecret, spec.CMPTrust.SignerCertificatesSecretRef)
	if configurationErr != nil {
		return runtimeConfiguration{}, configurationErr
	}
	renewalScheme := ""
	if spec.Endpoint.RenewalURL != "" {
		parsedRenewalEndpoint, parseErr := validateEndpointURL(spec.Endpoint.RenewalURL)
		if parseErr != nil {
			return runtimeConfiguration{}, permanentConfiguration("validate renewal endpoint", parseErr)
		}
		renewalScheme = parsedRenewalEndpoint.Scheme
	}
	tlsRoots, configurationErr := loadTLSRoots(getSecret, spec, parsedEndpoint.Scheme == schemeHTTPS || renewalScheme == schemeHTTPS)
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
	strictRFC9483 := spec.Protocol.ValidationProfile == cmpv1alpha1.ValidationProfileRFC9483
	if strictRFC9483 {
		standard := cmpv1alpha1.P10CRResponseCertReqIDStandard
		responseCertReqID = &standard
	}
	if spec.Protocol.P10CRResponseCertReqID != nil {
		pinned := *spec.Protocol.P10CRResponseCertReqID
		responseCertReqID = &pinned
	}
	requireKUPCAPubsAbsent := strictRFC9483 || spec.Protocol.KURResponseCAPubs == cmpv1alpha1.KURResponseCAPubsRequireAbsent
	request := protocol.EnrollmentRequest{
		EndpointURL:            spec.Endpoint.URL,
		Timeout:                spec.Endpoint.Timeout.Duration,
		MaxResponseSize:        spec.Endpoint.MaxResponseSize,
		Recipient:              recipient,
		ImplicitConfirm:        spec.Protocol.Confirmation == "Implicit",
		RejectGrantedMods:      spec.Policy.GrantedModifications != cmpv1alpha1.GrantedModificationsAccept,
		AllowSignedMACResponse: !strictRFC9483 && spec.Protocol.MACResponseProtection != cmpv1alpha1.MACResponseProtectionStrict,
		ResponseCertReqID:      responseCertReqID,
		RequireKUPCAPubsAbsent: requireKUPCAPubsAbsent,
		Protection:             protection,
		CMPTrust:               cmpTrust,
		CMPTrustCertificates:   cmpTrustCertificates,
		TLSRoots:               tlsRoots,
	}
	if sender != nil {
		request.Sender = sender
	}
	request.CMPResponseCertificates = responseCertificates
	fingerprints := credentialFingerprints(secrets)
	configurationDigest, err := runtimeConfigurationDigest(issuerReference(issuer), fingerprints)
	if err != nil {
		return runtimeConfiguration{}, permanentConfiguration("identify issuer configuration", err)
	}
	endpointScheme := parsedEndpoint.Scheme
	if renewalScheme == schemeHTTP {
		endpointScheme = schemeHTTP
	}
	return runtimeConfiguration{
		EndpointScheme:       endpointScheme,
		RenewalEndpointURL:   spec.Endpoint.RenewalURL,
		EnrollmentRequest:    request,
		Transaction:          transactionLimitsWithDefaults(spec.Transaction),
		ConfigurationDigest:  configurationDigest,
		ConfigurationSecrets: fingerprints,
	}, nil
}

// runtimeConfigurationDigest identifies the issuer generation and the Secret versions used by a transaction.
func runtimeConfigurationDigest(issuerRef cmpv1alpha1.TransactionIssuerReference, secrets map[types.NamespacedName]secretFingerprint) (string, error) {
	// DataDigest is omitted when empty so a digest computed over credential Secrets alone keeps the
	// encoding of earlier releases, which lets an unfinished P10CR transaction survive an upgrade.
	type secretIdentity struct {
		Namespace       string `json:"namespace"`
		Name            string `json:"name"`
		UID             string `json:"uid"`
		ResourceVersion string `json:"resourceVersion"`
		DataDigest      string `json:"dataDigest,omitempty"`
	}
	identities := make([]secretIdentity, 0, len(secrets))
	for key, fingerprint := range secrets {
		identities = append(identities, secretIdentity{Namespace: key.Namespace, Name: key.Name, UID: fingerprint.UID, ResourceVersion: fingerprint.ResourceVersion, DataDigest: fingerprint.DataDigest})
	}
	slices.SortFunc(identities, func(left secretIdentity, right secretIdentity) int {
		if namespaceOrder := strings.Compare(left.Namespace, right.Namespace); namespaceOrder != 0 {
			return namespaceOrder
		}
		return strings.Compare(left.Name, right.Name)
	})
	encoded, err := json.Marshal(struct {
		Issuer  cmpv1alpha1.TransactionIssuerReference `json:"issuer"`
		Secrets []secretIdentity                       `json:"secrets"`
	}{Issuer: issuerRef, Secrets: identities})
	if err != nil {
		return "", fmt.Errorf("encode runtime configuration identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
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
	renewalScheme := ""
	if spec.Endpoint.RenewalURL != "" {
		renewalEndpoint, err := validateEndpointURL(spec.Endpoint.RenewalURL)
		if err != nil {
			return nil, fmt.Errorf("renewal %w", err)
		}
		renewalScheme = renewalEndpoint.Scheme
	}
	if err := validateTransport(spec.Transport, endpoint.Scheme == schemeHTTPS || renewalScheme == schemeHTTPS); err != nil {
		return nil, err
	}
	if err := validateTransactionAndPolicy(spec.Transaction, spec.Policy); err != nil {
		return nil, err
	}
	return endpoint, nil
}

// validateEndpoint enforces complete bounded HTTP or HTTPS endpoint configuration.
func validateEndpoint(spec cmpv1alpha1.EndpointSpec) (*url.URL, error) {
	endpoint, err := validateEndpointURL(spec.URL)
	if err != nil {
		return nil, err
	}
	if spec.Timeout.Duration <= 0 || spec.MaxResponseSize < 1024 || spec.MaxResponseSize > 10485760 {
		return nil, fmt.Errorf("endpoint timeout or response size is outside supported bounds")
	}
	return endpoint, nil
}

// validateEndpointURL enforces one complete HTTP or HTTPS endpoint URL without embedded credentials.
func validateEndpointURL(value string) (*url.URL, error) {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != schemeHTTP && endpoint.Scheme != schemeHTTPS) {
		return nil, fmt.Errorf("endpoint URL must be a complete HTTP or HTTPS URL")
	}
	if endpoint.User != nil || endpoint.Fragment != "" {
		return nil, fmt.Errorf("endpoint URL user information and fragments are not supported")
	}
	return endpoint, nil
}

// validateProtocol checks enrollment, renewal, confirmation and response validation settings.
func validateProtocol(spec cmpv1alpha1.ProtocolSpec) error {
	if spec.Version != 2 || spec.InitialEnrollment != cmpv1alpha1.InitialEnrollmentP10CR {
		return fmt.Errorf("only CMPv2 P10CR initial enrollment is implemented")
	}
	if spec.CertProfile != "" {
		return fmt.Errorf("certProfile is reserved until its CMP encoding is implemented")
	}
	if spec.Renewal != "" && spec.Renewal != cmpv1alpha1.RenewalP10CR && spec.Renewal != cmpv1alpha1.RenewalKUR {
		return fmt.Errorf("renewal must be P10CR or KUR")
	}
	if spec.ValidationProfile != "" && spec.ValidationProfile != cmpv1alpha1.ValidationProfileInteroperable && spec.ValidationProfile != cmpv1alpha1.ValidationProfileRFC9483 {
		return fmt.Errorf("validationProfile must be Interoperable or RFC9483")
	}
	if spec.KURResponseCAPubs != "" && spec.KURResponseCAPubs != cmpv1alpha1.KURResponseCAPubsAccept && spec.KURResponseCAPubs != cmpv1alpha1.KURResponseCAPubsRequireAbsent {
		return fmt.Errorf("kurResponseCaPubs must be Accept or RequireAbsent")
	}
	if spec.Recipient == "" || (spec.Confirmation != "Explicit" && spec.Confirmation != "Implicit") {
		return fmt.Errorf("recipient and a supported confirmation policy are required")
	}
	if spec.P10CRResponseCertReqID != nil && *spec.P10CRResponseCertReqID != cmpv1alpha1.P10CRResponseCertReqIDStandard && *spec.P10CRResponseCertReqID != cmpv1alpha1.P10CRResponseCertReqIDLegacyZero {
		return fmt.Errorf("p10cr response certReqId must be -1 or 0")
	}
	// An empty value is an issuer written before the field existed, and it reads as the default the
	// schema applies to every new object.
	if spec.MACResponseProtection != "" && spec.MACResponseProtection != cmpv1alpha1.MACResponseProtectionStrict && spec.MACResponseProtection != cmpv1alpha1.MACResponseProtectionAllowSignature {
		return fmt.Errorf("macResponseProtection must be Strict or AllowSignature")
	}
	if spec.ValidationProfile == cmpv1alpha1.ValidationProfileRFC9483 {
		if spec.P10CRResponseCertReqID != nil && *spec.P10CRResponseCertReqID != cmpv1alpha1.P10CRResponseCertReqIDStandard {
			return fmt.Errorf("RFC9483 validation requires p10cr response certReqId -1")
		}
		if spec.MACResponseProtection != "" && spec.MACResponseProtection != cmpv1alpha1.MACResponseProtectionStrict {
			return fmt.Errorf("RFC9483 validation requires Strict macResponseProtection")
		}
		if spec.KURResponseCAPubs == cmpv1alpha1.KURResponseCAPubsAccept {
			return fmt.Errorf("RFC9483 validation requires KUP caPubs to be absent")
		}
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
		if _, _, err := passwordBasedMacAlgorithms(password.Algorithm); err != nil {
			return err
		}
		if password.Algorithm.IterationCount < cmpv1alpha1.PasswordBasedMacIterationCountMinimum || password.Algorithm.IterationCount > cmpv1alpha1.PasswordBasedMacIterationCountMaximum {
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

// passwordBasedMacAlgorithms maps supported API values to hashes and enforces the library's key length limit.
func passwordBasedMacAlgorithms(spec cmpv1alpha1.PasswordBasedMacAlgorithmSpec) (crypto.Hash, crypto.Hash, error) {
	owf := map[string]crypto.Hash{
		cmpv1alpha1.PasswordBasedMacOWFSHA256: crypto.SHA256,
		cmpv1alpha1.PasswordBasedMacOWFSHA384: crypto.SHA384,
		cmpv1alpha1.PasswordBasedMacOWFSHA512: crypto.SHA512,
	}[spec.OWF]
	mac := map[string]crypto.Hash{
		cmpv1alpha1.PasswordBasedMacMACHMACSHA256: crypto.SHA256,
		cmpv1alpha1.PasswordBasedMacMACHMACSHA384: crypto.SHA384,
		cmpv1alpha1.PasswordBasedMacMACHMACSHA512: crypto.SHA512,
	}[spec.MAC]
	if owf == 0 || mac == 0 || mac.Size() > owf.Size() {
		return 0, 0, fmt.Errorf("unsupported passwordBasedMac algorithm combination")
	}
	return owf, mac, nil
}

// validateTransport keeps TLS credentials separate and rejects unimplemented mTLS.
func validateTransport(spec cmpv1alpha1.TransportSpec, usesHTTPS bool) error {
	if spec.TLS != nil && spec.TLS.ClientCertificateSecretRef != nil {
		return fmt.Errorf("mTLS client certificates are reserved for a later release")
	}
	if !usesHTTPS && spec.TLS != nil && spec.TLS.CASecretRef != nil {
		return fmt.Errorf("TLS CA trust cannot be configured without an HTTPS endpoint")
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

// loadTrustPool retains the configured anchors for chain validation and response signer discovery.
func loadTrustPool(getSecret func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError), reference cmpv1alpha1.SecretKeyReference) (*x509.CertPool, []*x509.Certificate, *configurationError) {
	secret, err := getSecret(cmpv1alpha1.LocalSecretReference{Name: reference.Name})
	if err != nil {
		return nil, nil, err
	}
	data, valueErr := requiredSecretValue(secret, reference.Key)
	if valueErr != nil {
		return nil, nil, retryableConfiguration("read CMP trust", valueErr)
	}
	certificates, parseErr := protocol.ParseCertificates(data)
	if parseErr != nil {
		return nil, nil, retryableConfiguration("parse CMP trust", parseErr)
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, certificates, nil
}

// loadResponseCertificates reads optional response verification candidates without adding trust anchors.
func loadResponseCertificates(getSecret func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError), reference *cmpv1alpha1.SecretKeyReference) ([]*x509.Certificate, *configurationError) {
	if reference == nil {
		return nil, nil
	}
	if reference.Name == "" || reference.Key == "" {
		return nil, permanentConfiguration("validate CMP response signer reference", fmt.Errorf("name and key are required"))
	}
	secret, err := getSecret(cmpv1alpha1.LocalSecretReference{Name: reference.Name})
	if err != nil {
		return nil, err
	}
	data, valueErr := requiredSecretValue(secret, reference.Key)
	if valueErr != nil {
		return nil, retryableConfiguration("read CMP response signers", valueErr)
	}
	certificates, parseErr := protocol.ParseCertificates(data)
	if parseErr != nil {
		return nil, retryableConfiguration("parse CMP response signers", parseErr)
	}
	return certificates, nil
}

// loadTLSRoots parses optional HTTPS trust anchors.
func loadTLSRoots(getSecret func(cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError), spec *cmpv1alpha1.CMPIssuerSpec, usesHTTPS bool) (*x509.CertPool, *configurationError) {
	if !usesHTTPS || spec.Transport.TLS == nil || spec.Transport.TLS.CASecretRef == nil {
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
		owf, mac, algorithmErr := passwordBasedMacAlgorithms(password.Algorithm)
		if algorithmErr != nil {
			return protocol.Protection{}, permanentConfiguration("validate PasswordBasedMac algorithms", algorithmErr)
		}
		return protocol.Protection{Password: &protocol.PasswordProtection{Reference: reference, Secret: sharedSecret, IterationCount: int(password.Algorithm.IterationCount), OWF: owf, MAC: mac}}, nil
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

// permanentConfiguration constructs an immutable issuer configuration failure.
func permanentConfiguration(operation string, err error) *configurationError {
	return &configurationError{Permanent: true, Operation: operation, Err: err}
}

// retryableConfiguration constructs a Secret-backed issuer configuration failure.
func retryableConfiguration(operation string, err error) *configurationError {
	return &configurationError{Permanent: false, Operation: operation, Err: err}
}
