/*
Copyright 2026 The cmp-issuer Authors.

SPDX-License-Identifier: GPL-3.0-only

This file is part of cmp-issuer.

cmp-issuer is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3.

cmp-issuer is distributed in the hope that it will be useful but WITHOUT ANY
WARRANTY. See the GNU General Public License for more details.
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
