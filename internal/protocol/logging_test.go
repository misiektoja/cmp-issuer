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

import (
	"strings"
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
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
