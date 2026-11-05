/*
Copyright 2026 The cmp-issuer Authors.

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
	"crypto"
	"testing"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
)

// rejectedSignatureDigest is a digest the API does not offer.
const rejectedSignatureDigest = "SHA1"

// TestSignatureDigest verifies the API values map to their hashes, the empty value follows the key
// and an unknown value is refused by the protocol validation.
func TestSignatureDigest(t *testing.T) {
	for _, test := range []struct {
		value string
		want  crypto.Hash
	}{
		{value: "", want: 0},
		{value: cmpv1alpha1.SignatureDigestSHA256, want: crypto.SHA256},
		{value: cmpv1alpha1.SignatureDigestSHA384, want: crypto.SHA384},
		{value: cmpv1alpha1.SignatureDigestSHA512, want: crypto.SHA512},
	} {
		got, err := signatureDigest(test.value)
		if err != nil || got != test.want {
			t.Fatalf("signatureDigest(%q) = %v, %v; want %v", test.value, got, err, test.want)
		}
		spec := validSpec("https://cmp.example.test").Protocol
		spec.SignatureDigest = test.value
		if err := validateProtocol(spec); err != nil {
			t.Fatalf("validateProtocol rejected signatureDigest %q: %v", test.value, err)
		}
	}
	spec := validSpec("https://cmp.example.test").Protocol
	spec.SignatureDigest = rejectedSignatureDigest
	if err := validateProtocol(spec); err == nil {
		t.Fatal("expected validateProtocol to reject signatureDigest SHA1")
	}
}
