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
	"testing"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

// FuzzParsePKIMessage checks that arbitrary DER input never panics the parser.
func FuzzParsePKIMessage(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("not DER"))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = pkicmp.ParsePKIMessage(data) })
}
