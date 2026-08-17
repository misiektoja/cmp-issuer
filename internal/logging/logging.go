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

// Package logging bounds values that originate outside the controller before they reach a log line.
package logging

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxTextLength is the longest text a single log value carries.
	MaxTextLength = 256
	// MaxListItems is the largest number of entries a logged list carries before the rest is summarized.
	MaxListItems = 8
)

// Text replaces non-printing characters and truncates a value, so text from a peer can neither forge a log line nor flood the log.
func Text(value string) string {
	printable := strings.Map(func(character rune) rune {
		if unicode.IsGraphic(character) {
			return character
		}
		return ' '
	}, value)
	if utf8.RuneCountInString(printable) <= MaxTextLength {
		return printable
	}
	return string([]rune(printable)[:MaxTextLength]) + " ...(truncated)"
}

// List bounds every entry of a list and replaces the entries beyond the limit with their count.
func List(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	limit := min(len(values), MaxListItems)
	bounded := make([]string, 0, limit+1)
	for _, value := range values[:limit] {
		bounded = append(bounded, Text(value))
	}
	if len(values) > limit {
		bounded = append(bounded, fmt.Sprintf("(%d more)", len(values)-limit))
	}
	return bounded
}
