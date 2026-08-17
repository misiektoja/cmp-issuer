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

import (
	"strings"
	"testing"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// TestClassifyStatusBoundsServerText verifies text chosen by a CMP server cannot flood the controller
// log or forge a second log line through the failure it is reported in.
func TestClassifyStatusBoundsServerText(t *testing.T) {
	flood := strings.Repeat("a", 100000)
	status := pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, StatusString: pkicmp.PKIFreeText{"rejected\nby policy", flood}, FailInfo: pkicmp.FailBadRequest}
	err := classifyStatus(status)
	if err == nil {
		t.Fatal("expected a rejected status to be reported as a failure")
	}
	message := err.Error()
	if strings.ContainsAny(message, "\n\r") {
		t.Fatalf("expected line breaks to be removed, got %q", message)
	}
	if len(message) > 1024 {
		t.Fatalf("expected the server text to be bounded, got %d bytes", len(message))
	}
	if !strings.Contains(message, "badRequest") || !strings.Contains(message, "by policy") {
		t.Fatalf("expected the failure and the readable server text to survive, got %q", message)
	}
}

// TestClassifyStatusKeepsOrdinaryServerText verifies bounding does not rewrite a usable explanation.
func TestClassifyStatusKeepsOrdinaryServerText(t *testing.T) {
	status := pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, StatusString: pkicmp.PKIFreeText{"End entity is not authorized"}, FailInfo: pkicmp.FailNotAuthorized}
	err := classifyStatus(status)
	if err == nil {
		t.Fatal("expected a rejected status to be reported as a failure")
	}
	if !strings.Contains(err.Error(), "End entity is not authorized") {
		t.Fatalf("expected the server explanation to be preserved, got %q", err.Error())
	}
}
