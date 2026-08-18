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

package protocol

import "testing"

// TestParseDistinguishedName verifies supported attributes, escapes and invalid components.
func TestParseDistinguishedName(t *testing.T) {
	name, err := ParseDistinguishedName(`C=DE, O=NOKIA, CN=SubCA2k-256, OU=Lab\, CMP`)
	if err != nil {
		t.Fatalf("ParseDistinguishedName returned error: %v", err)
	}
	if name.CommonName != "SubCA2k-256" || len(name.Organization) != 1 || len(name.OrganizationalUnit) != 1 || name.OrganizationalUnit[0] != "Lab, CMP" {
		t.Fatalf("unexpected parsed name: %#v", name)
	}
	invalid := []string{"", "CN", "CN=", "CN=test\\", "UNKNOWN=value", "CN=test,,O=example"}
	for _, value := range invalid {
		if _, err := ParseDistinguishedName(value); err == nil {
			t.Errorf("expected %q to fail", value)
		}
	}
}

// TestParseCertificatesRejectsTrailingData verifies PEM bundles fail closed on extra data.
func TestParseCertificatesRejectsTrailingData(t *testing.T) {
	if _, err := ParseCertificates([]byte("not a certificate")); err == nil {
		t.Fatal("expected invalid certificate data to fail")
	}
}
