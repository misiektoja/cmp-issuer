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
