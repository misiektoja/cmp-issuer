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

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	// ProtectionTypePasswordBasedMac selects RFC 4210 PasswordBasedMac protection.
	ProtectionTypePasswordBasedMac = "PasswordBasedMac"
	// ProtectionTypeSignature selects certificate-based signature protection.
	ProtectionTypeSignature = "Signature"
	// InitialEnrollmentP10CR selects PKCS #10 initial enrollment.
	InitialEnrollmentP10CR = "P10CR"
	// P10CRResponseCertReqIDStandard pins the response identifier required by RFC 9810 and RFC 9483.
	P10CRResponseCertReqIDStandard int64 = -1
	// P10CRResponseCertReqIDLegacyZero pins the response identifier returned by servers that reuse the CRMF index.
	P10CRResponseCertReqIDLegacyZero int64 = 0
	// MACResponseProtectionStrict requires a PasswordBasedMac request to be answered with MAC-based protection.
	MACResponseProtectionStrict = "Strict"
	// MACResponseProtectionAllowSignature also accepts a signature-protected answer that chains to a CMP trust anchor.
	MACResponseProtectionAllowSignature = "AllowSignature"
	// GrantedModificationsReject rejects certificates issued with modified identity fields.
	GrantedModificationsReject = "Reject"
	// GrantedModificationsAccept accepts validated certificates with server modifications.
	GrantedModificationsAccept = "Accept"
)

// CMPIssuerSpec defines the desired CMP endpoint, protection and transaction policy.
type CMPIssuerSpec struct {
	// Endpoint configures CMP transport behavior.
	// +required
	Endpoint EndpointSpec `json:"endpoint"`
	// Protocol configures the CMP operation and header identities.
	// +required
	Protocol ProtocolSpec `json:"protocol"`
	// Protection configures the mandatory CMP message protection mode.
	// +required
	Protection ProtectionSpec `json:"protection"`
	// CMPTrust configures trust anchors for CMP response protection and issued chains.
	// +required
	CMPTrust CMPTrustSpec `json:"cmpTrust"`
	// Transport configures optional TLS transport trust independently of CMP trust.
	// +optional
	Transport TransportSpec `json:"transport,omitempty"`
	// Transaction bounds a CMP enrollment transaction.
	// +kubebuilder:default={maximumDuration:"10m",minimumPollInterval:"1s",maximumPollInterval:"5m",maximumPolls:60}
	// +optional
	Transaction TransactionSpec `json:"transaction,omitempty"`
	// Policy configures certificate acceptance decisions.
	// +kubebuilder:default={grantedModifications:Reject}
	// +optional
	Policy PolicySpec `json:"policy,omitempty"`
}

// EndpointSpec configures the explicit CMP HTTP endpoint.
type EndpointSpec struct {
	// URL is the complete HTTP or HTTPS CMP endpoint URL.
	// +kubebuilder:validation:Pattern=`^https?://[^[:space:]]+$`
	// +required
	URL string `json:"url"`
	// Timeout bounds one HTTP exchange.
	// +kubebuilder:default="30s"
	// +required
	Timeout metav1.Duration `json:"timeout"`
	// MaxResponseSize is the maximum accepted CMP response body in bytes.
	// +kubebuilder:default=1048576
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=10485760
	// +required
	MaxResponseSize int64 `json:"maxResponseSize"`
}

// ProtocolSpec configures the initial CMP operation and message header.
type ProtocolSpec struct {
	// Version is the CMP protocol version number.
	// +kubebuilder:default=2
	// +kubebuilder:validation:Enum=2
	// +required
	Version int32 `json:"version"`
	// InitialEnrollment selects the enrollment request body.
	// Only P10CR is implemented. IR requires CRMF proof of possession over the workload private key,
	// which needs the key access design recorded in the threat model, so it is not accepted yet.
	// +kubebuilder:default=P10CR
	// +kubebuilder:validation:Enum=P10CR
	// +required
	InitialEnrollment string `json:"initialEnrollment"`
	// P10CRResponseCertReqID pins the exact certReqId required in CP and echoed in certConf.
	// Omit this field to accept the standards-defined value -1 or the widely deployed legacy value 0
	// and echo the received value. Set it to reject every other value for a known server.
	// +kubebuilder:validation:Enum=-1;0
	// +optional
	P10CRResponseCertReqID *int64 `json:"p10crResponseCertReqId,omitempty"`
	// MACResponseProtection selects which response protection answers a PasswordBasedMac request.
	// AllowSignature, the default, accepts either MAC-based protection or a signature whose signer
	// chains to cmpTrust and whose sender names spec.protocol.recipient, which is the same authority
	// check a Signature issuer already relies on for every response. RFC 9483 section 5 permits that
	// substitution and many servers send it, including any EJBCA CMP alias left at its own default of
	// responseprotection signature. Strict requires MAC-based protection throughout, so the shared
	// secret authenticates every message of the operation rather than only the request. Set it where
	// the trust anchor is shared with authorities that must not be able to answer, or to conform to a
	// profile that requires one protection type for a whole operation.
	// +kubebuilder:default=AllowSignature
	// +kubebuilder:validation:Enum=Strict;AllowSignature
	// +optional
	MACResponseProtection string `json:"macResponseProtection,omitempty"`
	// CertProfile is an optional server-side certificate profile identifier.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	CertProfile string `json:"certProfile,omitempty"`
	// Sender is an optional RFC 4514 distinguished name for the CMP sender.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Sender string `json:"sender,omitempty"`
	// Recipient is the RFC 4514 distinguished name for the CMP recipient.
	// +kubebuilder:validation:MaxLength=1024
	// +required
	Recipient string `json:"recipient"`
	// Confirmation selects explicit certConf or requests implicit confirmation.
	// +kubebuilder:default=Explicit
	// +kubebuilder:validation:Enum=Explicit;Implicit
	// +required
	Confirmation string `json:"confirmation"`
}

// ProtectionSpec selects exactly one CMP protection credential source.
// +kubebuilder:validation:XValidation:rule="self.type == 'PasswordBasedMac' ? has(self.passwordBasedMac) && !has(self.signature) : has(self.signature) && !has(self.passwordBasedMac)",message="exactly the protection configuration selected by type must be present"
type ProtectionSpec struct {
	// Type is the CMP message protection mode.
	// +kubebuilder:validation:Enum=PasswordBasedMac;Signature
	// +required
	Type string `json:"type"`
	// PasswordBasedMac configures shared-secret CMP protection.
	// +optional
	PasswordBasedMac *PasswordBasedMacSpec `json:"passwordBasedMac,omitempty"`
	// Signature configures certificate-based CMP protection.
	// +optional
	Signature *SignatureProtectionSpec `json:"signature,omitempty"`
}

// PasswordBasedMacSpec locates separate reference and shared-secret values.
type PasswordBasedMacSpec struct {
	// SecretRef names the Secret containing the reference and shared secret.
	// +required
	SecretRef LocalSecretReference `json:"secretRef"`
	// ReferenceKey selects the reference value key in Secret data.
	// +kubebuilder:default=reference
	// +required
	ReferenceKey string `json:"referenceKey"`
	// SecretKey selects the shared secret key in Secret data.
	// +kubebuilder:default=secret
	// +required
	SecretKey string `json:"secretKey"`
	// Algorithm configures PasswordBasedMac parameters without downgrade behavior.
	// +optional
	Algorithm PasswordBasedMacAlgorithmSpec `json:"algorithm,omitempty"`
}

// PasswordBasedMacAlgorithmSpec configures the initial supported PBM suite.
type PasswordBasedMacAlgorithmSpec struct {
	// OWF selects the one-way function.
	// +kubebuilder:default=SHA256
	// +kubebuilder:validation:Enum=SHA256
	// +required
	OWF string `json:"owf"`
	// MAC selects the message authentication algorithm.
	// +kubebuilder:default=HMACSHA256
	// +kubebuilder:validation:Enum=HMACSHA256
	// +required
	MAC string `json:"mac"`
	// IterationCount selects the PBM iteration count.
	// +kubebuilder:default=1024
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=1048575
	// +required
	IterationCount int32 `json:"iterationCount"`
}

// SignatureProtectionSpec locates bootstrap certificate protection material.
type SignatureProtectionSpec struct {
	// SecretRef names the Secret containing bootstrap material.
	// +required
	SecretRef LocalSecretReference `json:"secretRef"`
	// CertificateKey selects the bootstrap certificate in Secret data.
	// +kubebuilder:default="tls.crt"
	// +required
	CertificateKey string `json:"certificateKey"`
	// PrivateKeyKey selects the bootstrap private key in Secret data.
	// +kubebuilder:default="tls.key"
	// +required
	PrivateKeyKey string `json:"privateKeyKey"`
	// ChainKey optionally selects PEM-encoded bootstrap intermediates.
	// +optional
	ChainKey string `json:"chainKey,omitempty"`
}

// LocalSecretReference names a Secret whose namespace is fixed by issuer scope.
type LocalSecretReference struct {
	// Name is the Secret name.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}

// SecretKeyReference names a Secret and one key within its data.
type SecretKeyReference struct {
	// Name is the Secret name.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
	// Key is the Secret data key.
	// +kubebuilder:validation:MinLength=1
	// +required
	Key string `json:"key"`
}

// CMPTrustSpec configures CMP signer and issued-chain trust.
type CMPTrustSpec struct {
	// CASecretRef selects PEM-encoded trust anchors.
	// +required
	CASecretRef SecretKeyReference `json:"caSecretRef"`
}

// TransportSpec configures transport security separately from CMP protection.
type TransportSpec struct {
	// TLS configures HTTPS trust and reserves mTLS credentials for a later release.
	// +optional
	TLS *TLSTransportSpec `json:"tls,omitempty"`
}

// TLSTransportSpec configures HTTPS transport trust.
type TLSTransportSpec struct {
	// CASecretRef optionally selects PEM-encoded HTTPS trust anchors.
	// +optional
	CASecretRef *SecretKeyReference `json:"caSecretRef,omitempty"`
	// ClientCertificateSecretRef reserves a Secret for later mTLS support.
	// +optional
	ClientCertificateSecretRef *LocalSecretReference `json:"clientCertificateSecretRef,omitempty"`
}

// TransactionSpec configures limits for current and future asynchronous flows.
type TransactionSpec struct {
	// MaximumDuration bounds the complete transaction.
	// +kubebuilder:default="10m"
	// +required
	MaximumDuration metav1.Duration `json:"maximumDuration"`
	// MinimumPollInterval limits server-requested short poll delays.
	// +kubebuilder:default="1s"
	// +required
	MinimumPollInterval metav1.Duration `json:"minimumPollInterval"`
	// MaximumPollInterval limits server-requested long poll delays.
	// +kubebuilder:default="5m"
	// +required
	MaximumPollInterval metav1.Duration `json:"maximumPollInterval"`
	// MaximumPolls bounds asynchronous poll requests.
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	// +required
	MaximumPolls int32 `json:"maximumPolls"`
}

// PolicySpec configures certificate acceptance policy.
type PolicySpec struct {
	// GrantedModifications controls certificates returned with grantedWithMods.
	// +kubebuilder:default=Reject
	// +kubebuilder:validation:Enum=Reject;Accept
	// +required
	GrantedModifications string `json:"grantedModifications"`
}

// CMPIssuerStatus defines the observed issuer readiness conditions.
type CMPIssuerStatus struct {
	// Conditions represent the current issuer state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
