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

// Package chart holds tests over the packaged Helm chart's shipped content.
package chart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// crdKinds names the plural of every CRD the chart templates alongside config/crd/bases.
var crdKinds = []string{"cmpissuers", "cmpclusterissuers", "cmptransactions"}

// The chart carries its own copy of each CRD rather than rendering the generated file, so that the
// templates can wrap it in crd.enabled and the resource-policy annotation. Nothing regenerates that
// copy, so a schema change reaches an installer-manifest user and silently misses every Helm user.
// That is not hypothetical: the passwordBasedMac algorithm default fixed after 0.1.0 had to be copied
// across by hand, and had it not been, helm install would still have shipped the broken schema.

// generatedSpec returns the schema portion of a generated CRD, which is everything from the spec key on.
func generatedSpec(t *testing.T, plural string) string {
	t.Helper()
	path := filepath.Join("..", "..", "config", "crd", "bases", "certmanager.misiektoja.github.io_"+plural+".yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	index := strings.Index(string(content), "\nspec:\n")
	if index < 0 {
		t.Fatalf("%s: no spec block", path)
	}
	return strings.TrimRight(string(content)[index+1:], "\n")
}

// chartSpec returns the schema portion of the chart's copy, without the Helm conditional that closes it.
func chartSpec(t *testing.T, plural string) string {
	t.Helper()
	name := plural + ".certmanager.misiektoja.github.io.yaml"
	path := filepath.Join("..", "..", "charts", "cmp-issuer", "templates", "crd", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	index := strings.Index(string(content), "\nspec:\n")
	if index < 0 {
		t.Fatalf("%s: no spec block", path)
	}
	body := strings.TrimRight(string(content)[index+1:], "\n")
	return strings.TrimRight(strings.TrimSuffix(body, "{{- end }}"), "\n")
}

// TestChartCRDsMatchGeneratedCRDs keeps the chart's schema identical to the one controller-gen writes.
func TestChartCRDsMatchGeneratedCRDs(t *testing.T) {
	for _, plural := range crdKinds {
		t.Run(plural, func(t *testing.T) {
			generated, packaged := generatedSpec(t, plural), chartSpec(t, plural)
			if generated == packaged {
				return
			}
			generatedLines, packagedLines := strings.Split(generated, "\n"), strings.Split(packaged, "\n")
			for i := 0; i < len(generatedLines) || i < len(packagedLines); i++ {
				var left, right string
				if i < len(generatedLines) {
					left = generatedLines[i]
				}
				if i < len(packagedLines) {
					right = packagedLines[i]
				}
				if left != right {
					t.Fatalf("the chart copy of %s has drifted from config/crd/bases at line %d of the spec block.\n"+
						"  generated: %q\n  chart:     %q\n"+
						"Copy the generated spec into charts/cmp-issuer/templates/crd after running make manifests.",
						plural, i+1, left, right)
				}
			}
		})
	}
}
