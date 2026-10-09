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
	"errors"
	"testing"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
)

const testResponseSignerSecretName = "cmp-response-signers"

// TestLoadResponseCertificatesPreservesTrust verifies candidate Secrets stay within issuer scope and do not add roots.
func TestLoadResponseCertificatesPreservesTrust(t *testing.T) {
	for _, clusterScoped := range []bool{false, true} {
		namespace := testIssuerNamespace
		name := "namespaced"
		if clusterScoped {
			namespace = testClusterResourceNamespace
			name = "cluster"
		}
		t.Run(name, func(t *testing.T) {
			auth, trust, root := credentialSecrets(t, namespace)
			responseSigner, _, data := testCertificateMaterial(t, "CMP Responder")
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testResponseSignerSecretName, Namespace: namespace}, Data: map[string][]byte{testCMPTrustKey: data}}
			spec := validSpec("https://example.test/cmp")
			spec.CMPTrust.SignerCertificatesSecretRef = &cmpv1alpha1.SecretKeyReference{Name: secret.Name, Key: testCMPTrustKey}
			var issuer issuerapi.Issuer = &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: namespace}, Spec: spec}
			if clusterScoped {
				issuer = &cmpv1alpha1.CMPClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName}, Spec: spec}
			}
			kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust, secret).Build()
			signer := &Signer{KubeClient: kube, ClusterResourceNamespace: testClusterResourceNamespace}
			configuration, err := signer.loadRuntimeConfiguration(context.Background(), issuer)
			if err != nil {
				t.Fatal(err)
			}
			candidates := configuration.EnrollmentRequest.CMPResponseCertificates
			if len(candidates) != 1 || !candidates[0].Equal(responseSigner) {
				t.Fatal("expected the configured response signer candidate")
			}
			expectedRoots := x509.NewCertPool()
			expectedRoots.AddCert(root)
			if !expectedRoots.Equal(configuration.EnrollmentRequest.CMPTrust) {
				t.Fatal("response signer configuration changed the trust anchors")
			}
			if _, exists := configuration.ConfigurationSecrets[types.NamespacedName{Namespace: namespace, Name: secret.Name}]; !exists {
				t.Fatal("response signer Secret is missing from the transaction configuration")
			}
			wrongNamespace := secret.DeepCopy()
			wrongNamespace.Namespace = "other"
			wrongNamespace.ResourceVersion = ""
			if err := kube.Delete(context.Background(), secret); err != nil {
				t.Fatal(err)
			}
			if err := kube.Create(context.Background(), wrongNamespace); err != nil {
				t.Fatal(err)
			}
			if _, err := signer.loadRuntimeConfiguration(context.Background(), issuer); err == nil {
				t.Fatal("expected the issuer to reject a response signer Secret from another namespace")
			}
		})
	}
}

// TestLoadResponseCertificatesRejectsInvalidConfiguration checks references and malformed certificate data.
func TestLoadResponseCertificatesRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name      string
		reference cmpv1alpha1.SecretKeyReference
		data      map[string][]byte
		permanent bool
	}{
		{name: "missing name", reference: cmpv1alpha1.SecretKeyReference{Key: testCMPTrustKey}, permanent: true},
		{name: "missing key", reference: cmpv1alpha1.SecretKeyReference{Name: testResponseSignerSecretName}, permanent: true},
		{name: "absent data", reference: cmpv1alpha1.SecretKeyReference{Name: testResponseSignerSecretName, Key: testCMPTrustKey}},
		{name: "invalid certificate", reference: cmpv1alpha1.SecretKeyReference{Name: testResponseSignerSecretName, Key: testCMPTrustKey}, data: map[string][]byte{testCMPTrustKey: []byte("invalid certificate")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			getSecret := func(_ cmpv1alpha1.LocalSecretReference) (*corev1.Secret, *configurationError) {
				return &corev1.Secret{Data: test.data}, nil
			}
			_, err := loadResponseCertificates(getSecret, &test.reference)
			if err == nil || err.Permanent != test.permanent {
				t.Fatalf("expected configuration failure with permanent=%t, got %v", test.permanent, err)
			}
		})
	}
}

// TestSignRejectsResponseSignerRotationDuringTransaction binds resumed exchanges to the original signer Secret.
func TestSignRejectsResponseSignerRotationDuringTransaction(t *testing.T) {
	fixture := newAsyncFixture(t, []fakeExchange{{result: waitingResult(0, "nonce", 0)}})
	_, key, data := testCertificateMaterial(t, "CMP Responder")
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: testResponseSignerSecretName, Namespace: testIssuerNamespace}, Data: map[string][]byte{testCMPTrustKey: data}}
	if err := fixture.kube.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	fixture.issuer.Spec.CMPTrust.SignerCertificatesSecretRef = &cmpv1alpha1.SecretKeyReference{Name: secret.Name, Key: testCMPTrustKey}
	if _, err := fixture.sign(t); err == nil {
		t.Fatal("expected a pending transaction")
	}
	secret.Data[testCMPTrustKey] = testKURCertificate(t, key)
	if err := fixture.kube.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.sign(t)
	var permanent issuersigner.PermanentError
	if !errors.As(err, &permanent) || fixture.protocol.polls != 0 {
		t.Fatalf("expected the rotated response signer Secret to prevent polling, got %v", err)
	}
}

// TestResponseSignerReferenceAgainstAPIServer checks optional references survive schema admission and require both fields.
func TestResponseSignerReferenceAgainstAPIServer(t *testing.T) {
	kube := startEnvtest(t)
	for _, test := range []struct {
		name      string
		reference *cmpv1alpha1.SecretKeyReference
		valid     bool
	}{
		{name: "omitted", valid: true},
		{name: "complete", reference: &cmpv1alpha1.SecretKeyReference{Name: testResponseSignerSecretName, Key: testCMPTrustKey}, valid: true},
		{name: "missing-name", reference: &cmpv1alpha1.SecretKeyReference{Key: testCMPTrustKey}},
		{name: "missing-key", reference: &cmpv1alpha1.SecretKeyReference{Name: testResponseSignerSecretName}},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer := &cmpv1alpha1.CMPClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: test.name}, Spec: validSpec("https://example.test/cmp")}
			issuer.Spec.CMPTrust.SignerCertificatesSecretRef = test.reference
			err := kube.Create(context.Background(), issuer)
			if (err == nil) != test.valid {
				t.Fatalf("expected valid=%t, got %v", test.valid, err)
			}
			if test.valid {
				stored := &cmpv1alpha1.CMPClusterIssuer{}
				if err := kube.Get(context.Background(), types.NamespacedName{Name: test.name}, stored); err != nil {
					t.Fatal(err)
				}
				reference := stored.Spec.CMPTrust.SignerCertificatesSecretRef
				if (reference == nil) != (test.reference == nil) || reference != nil && *reference != *test.reference {
					t.Fatal("response signer reference changed during admission")
				}
			}
		})
	}
}
