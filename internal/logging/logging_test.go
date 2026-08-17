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

package logging

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTextReplacesNonPrintingCharacters verifies a peer cannot inject line breaks into the log.
func TestTextReplacesNonPrintingCharacters(t *testing.T) {
	bounded := Text("rejected\n{\"level\":\"info\",\"msg\":\"forged\"}\r\tdetail\u2028end")
	if strings.ContainsAny(bounded, "\n\r\t\u2028") {
		t.Fatalf("expected non-printing characters to be replaced, got %q", bounded)
	}
	if !strings.Contains(bounded, "rejected") || !strings.Contains(bounded, "detail") {
		t.Fatalf("expected the readable text to survive, got %q", bounded)
	}
}

// TestTextTruncatesLongValues verifies server-supplied text cannot flood one log line.
func TestTextTruncatesLongValues(t *testing.T) {
	bounded := Text(strings.Repeat("a", 10*MaxTextLength))
	if !strings.HasSuffix(bounded, "...(truncated)") {
		t.Fatalf("expected a truncation marker, got %q", bounded)
	}
	if utf8.RuneCountInString(bounded) > MaxTextLength+len(" ...(truncated)") {
		t.Fatalf("expected the value to be bounded, got %d characters", utf8.RuneCountInString(bounded))
	}
}

// TestTextKeepsShortValuesUnchanged verifies bounding does not rewrite ordinary text.
func TestTextKeepsShortValuesUnchanged(t *testing.T) {
	if bounded := Text("CN=workload, O=Example"); bounded != "CN=workload, O=Example" {
		t.Fatalf("expected the value to be unchanged, got %q", bounded)
	}
}

// TestListBoundsEntriesAndCountsTheRest verifies a long list is summarized rather than logged whole.
func TestListBoundsEntriesAndCountsTheRest(t *testing.T) {
	values := make([]string, 0, MaxListItems+3)
	for range MaxListItems + 3 {
		values = append(values, "host.example.test")
	}
	bounded := List(values)
	if len(bounded) != MaxListItems+1 {
		t.Fatalf("expected %d entries, got %d", MaxListItems+1, len(bounded))
	}
	if bounded[len(bounded)-1] != "(3 more)" {
		t.Fatalf("expected the remaining entries to be counted, got %q", bounded[len(bounded)-1])
	}
	if List(nil) != nil {
		t.Fatal("expected an empty list to stay empty")
	}
}
