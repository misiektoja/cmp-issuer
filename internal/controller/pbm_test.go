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
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
)

// pbmAlgorithmCase describes the supported API combinations and their protocol hashes.
type pbmAlgorithmCase struct {
	owf     string
	mac     string
	owfHash crypto.Hash
	macHash crypto.Hash
	valid   bool
}

var pbmAlgorithmCases = []pbmAlgorithmCase{
	{cmpv1alpha1.PasswordBasedMacOWFSHA256, cmpv1alpha1.PasswordBasedMacMACHMACSHA256, crypto.SHA256, crypto.SHA256, true},
	{cmpv1alpha1.PasswordBasedMacOWFSHA256, cmpv1alpha1.PasswordBasedMacMACHMACSHA384, crypto.SHA256, crypto.SHA384, false},
	{cmpv1alpha1.PasswordBasedMacOWFSHA256, cmpv1alpha1.PasswordBasedMacMACHMACSHA512, crypto.SHA256, crypto.SHA512, false},
	{cmpv1alpha1.PasswordBasedMacOWFSHA384, cmpv1alpha1.PasswordBasedMacMACHMACSHA256, crypto.SHA384, crypto.SHA256, true},
	{cmpv1alpha1.PasswordBasedMacOWFSHA384, cmpv1alpha1.PasswordBasedMacMACHMACSHA384, crypto.SHA384, crypto.SHA384, true},
	{cmpv1alpha1.PasswordBasedMacOWFSHA384, cmpv1alpha1.PasswordBasedMacMACHMACSHA512, crypto.SHA384, crypto.SHA512, false},
	{cmpv1alpha1.PasswordBasedMacOWFSHA512, cmpv1alpha1.PasswordBasedMacMACHMACSHA256, crypto.SHA512, crypto.SHA256, true},
	{cmpv1alpha1.PasswordBasedMacOWFSHA512, cmpv1alpha1.PasswordBasedMacMACHMACSHA384, crypto.SHA512, crypto.SHA384, true},
	{cmpv1alpha1.PasswordBasedMacOWFSHA512, cmpv1alpha1.PasswordBasedMacMACHMACSHA512, crypto.SHA512, crypto.SHA512, true},
	{"SHA1", cmpv1alpha1.PasswordBasedMacMACHMACSHA256, crypto.SHA1, crypto.SHA256, false},
	{cmpv1alpha1.PasswordBasedMacOWFSHA256, "HMACSHA1", crypto.SHA256, crypto.SHA1, false},
}

// TestPBMAlgorithmConfiguration verifies API algorithm choices reach the protocol request without downgrade.
func TestPBMAlgorithmConfiguration(t *testing.T) {
	for _, test := range pbmAlgorithmCases {
		t.Run(test.owf+"/"+test.mac, func(t *testing.T) {
			auth, trust, _ := credentialSecrets(t, testIssuerNamespace)
			kube := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(auth, trust).Build()
			signer := &Signer{KubeClient: kube}
			issuer := &cmpv1alpha1.CMPIssuer{ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testIssuerNamespace}, Spec: validSpec("https://example.test/cmp")}
			issuer.Spec.Protection.PasswordBasedMac.Algorithm.OWF = test.owf
			issuer.Spec.Protection.PasswordBasedMac.Algorithm.MAC = test.mac
			configuration, err := signer.loadRuntimeConfiguration(context.Background(), issuer)
			if (err == nil) != test.valid {
				t.Fatalf("expected valid=%t, got %v", test.valid, err)
			}
			if test.valid {
				password := configuration.EnrollmentRequest.Protection.Password
				if password == nil || password.OWF != test.owfHash || password.MAC != test.macHash {
					t.Fatal("configured PBM hashes were not forwarded")
				}
			}
		})
	}
}

// TestPBMAlgorithmsAgainstAPIServer verifies admission accepts supported combinations and rejects key expansion.
func TestPBMAlgorithmsAgainstAPIServer(t *testing.T) {
	kube := startEnvtest(t)
	for i, test := range pbmAlgorithmCases {
		t.Run(test.owf+"/"+test.mac, func(t *testing.T) {
			issuer := &cmpv1alpha1.CMPClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pbm-%d", i)}, Spec: validSpec("https://example.test/cmp")}
			issuer.Spec.Protection.PasswordBasedMac.Algorithm.OWF = test.owf
			issuer.Spec.Protection.PasswordBasedMac.Algorithm.MAC = test.mac
			err := kube.Create(context.Background(), issuer)
			if (err == nil) != test.valid {
				t.Fatalf("expected valid=%t, got %v", test.valid, err)
			}
			if test.valid {
				stored := &cmpv1alpha1.CMPClusterIssuer{}
				if err := kube.Get(context.Background(), types.NamespacedName{Name: issuer.Name}, stored); err != nil {
					t.Fatal(err)
				}
				algorithm := stored.Spec.Protection.PasswordBasedMac.Algorithm
				if algorithm.OWF != test.owf || algorithm.MAC != test.mac {
					t.Fatal("admission changed the selected PBM algorithms")
				}
			}
		})
	}
}
