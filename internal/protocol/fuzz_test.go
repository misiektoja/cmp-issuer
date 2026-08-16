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
	"testing"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// FuzzParsePKIMessage checks that arbitrary DER input never panics the parser.
func FuzzParsePKIMessage(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("not DER"))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = pkicmp.ParsePKIMessage(data) })
}
