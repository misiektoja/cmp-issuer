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

package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
)

// A documented example is only correct if it survives the API server and then the controller. Reading
// one proves neither, because the two reject different things at different times. Schema defaulting in
// particular descends only into an object the request actually carries, so a nested block that carries
// defaults on its fields but none on the block itself is silently absent when the example omits it, and
// the controller sees a zero value the API server was happy with. That is exactly how the quick start
// issuer shipped in 0.1.0 rejecting itself with "unsupported passwordBasedMac algorithm parameters".
// These tests paste the shipped examples the way a reader would.

// docExample is one complete API object lifted out of the shipped documentation.
type docExample struct {
	file    string
	line    int
	kind    string
	name    string
	content []byte
}

// fencedBlock matches a fenced code block and captures its language and body.
var fencedBlock = regexp.MustCompile("(?s)```([A-Za-z]*)\n(.*?)```")

// heredocBody matches the YAML a kubectl apply heredoc feeds in, which is how the quick start reads.
var heredocBody = regexp.MustCompile(`(?s)<<'EOF'\n(.*?)\nEOF`)

// documentationFiles lists every shipped Markdown page, so a new page is covered without editing this test.
func documentationFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	files := []string{filepath.Join(root, "README.md")}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk documentation: %v", err)
	}
	return files
}

// collectDocumentedIssuers extracts every complete CMPIssuer and CMPClusterIssuer example from the documentation.
func collectDocumentedIssuers(t *testing.T) []docExample {
	t.Helper()
	var examples []docExample
	for _, file := range documentationFiles(t) {
		text, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, block := range fencedBlock.FindAllSubmatchIndex(text, -1) {
			language := string(text[block[2]:block[3]])
			body := text[block[4]:block[5]]
			// A YAML fence is the example itself. Any other fence is a shell snippet, where the
			// example reaches the cluster through a kubectl apply heredoc.
			candidates := [][]byte{}
			if language == "yaml" || language == "yml" {
				candidates = append(candidates, body)
			} else {
				for _, heredoc := range heredocBody.FindAllSubmatch(body, -1) {
					candidates = append(candidates, heredoc[1])
				}
			}
			line := 1 + strings.Count(string(text[:block[0]]), "\n")
			for _, candidate := range candidates {
				for document := range strings.SplitSeq(string(candidate), "\n---\n") {
					if example, ok := parseIssuerExample(file, line, []byte(document)); ok {
						examples = append(examples, example)
					}
				}
			}
		}
	}
	return examples
}

// parseIssuerExample reports whether a document is one of this project's issuer kinds and returns it.
func parseIssuerExample(file string, line int, document []byte) (docExample, bool) {
	if strings.TrimSpace(string(document)) == "" {
		return docExample{}, false
	}
	var header metav1.TypeMeta
	if err := yaml.Unmarshal(document, &header); err != nil {
		return docExample{}, false
	}
	if !strings.HasPrefix(header.APIVersion, cmpv1alpha1.GroupVersion.Group+"/") {
		return docExample{}, false
	}
	if header.Kind != "CMPIssuer" && header.Kind != "CMPClusterIssuer" {
		return docExample{}, false
	}
	var object unstructured.Unstructured
	if err := yaml.Unmarshal(document, &object); err != nil {
		return docExample{}, false
	}
	return docExample{file: file, line: line, kind: header.Kind, name: object.GetName(), content: document}, true
}

// TestDocumentedIssuerExamplesApplyAndValidate applies every documented issuer to a real API server and validates it.
func TestDocumentedIssuerExamplesApplyAndValidate(t *testing.T) {
	examples := collectDocumentedIssuers(t)
	// The extraction is silent when a page moves or a fence changes shape, so an empty result is a
	// broken test rather than a clean run.
	if len(examples) == 0 {
		t.Fatal("no documented CMPIssuer or CMPClusterIssuer examples were found, the extraction is broken")
	}
	kubeClient := startEnvtest(t)
	ctx := context.Background()
	for index, example := range examples {
		t.Run(fmt.Sprintf("%s_%s_%s", filepath.Base(example.file), example.kind, example.name), func(t *testing.T) {
			var object unstructured.Unstructured
			if err := yaml.Unmarshal(example.content, &object); err != nil {
				t.Fatalf("%s:%d: parse example: %v", example.file, example.line, err)
			}
			// Each example gets its own namespace, so two pages may document the same issuer name.
			namespace := fmt.Sprintf("cmp-docs-%d", index)
			if object.GetKind() == "CMPIssuer" {
				if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
					t.Fatalf("create namespace: %v", err)
				}
				object.SetNamespace(namespace)
			} else {
				object.SetName(fmt.Sprintf("%s-%d", object.GetName(), index))
			}
			// Created exactly as documented, so the API server applies the same defaults a reader gets.
			if err := kubeClient.Create(ctx, &object); err != nil {
				t.Fatalf("%s:%d: the documented %s is rejected by the API server: %v", example.file, example.line, example.kind, err)
			}
			spec := loadDocumentedIssuerSpec(t, ctx, kubeClient, object)
			if _, err := validateSpec(spec); err != nil {
				t.Fatalf("%s:%d: the documented %s is accepted by the API server but rejected by the controller: %v", example.file, example.line, example.kind, err)
			}
		})
	}
}

// loadDocumentedIssuerSpec reads the created example back, so the spec carries every default the API server applied.
func loadDocumentedIssuerSpec(t *testing.T, ctx context.Context, kubeClient client.Client, object unstructured.Unstructured) *cmpv1alpha1.CMPIssuerSpec {
	t.Helper()
	key := types.NamespacedName{Name: object.GetName(), Namespace: object.GetNamespace()}
	if object.GetKind() == "CMPClusterIssuer" {
		var clusterIssuer cmpv1alpha1.CMPClusterIssuer
		if err := kubeClient.Get(ctx, key, &clusterIssuer); err != nil {
			t.Fatalf("read back the created CMPClusterIssuer: %v", err)
		}
		return &clusterIssuer.Spec
	}
	var issuer cmpv1alpha1.CMPIssuer
	if err := kubeClient.Get(ctx, key, &issuer); err != nil {
		t.Fatalf("read back the created CMPIssuer: %v", err)
	}
	return &issuer.Spec
}

// TestOmittableObjectsCarryTheirOwnDefault guards the defaulting rule the quick start issuer tripped on.
func TestOmittableObjectsCarryTheirOwnDefault(t *testing.T) {
	kubeClient := startEnvtest(t)
	ctx := context.Background()
	namespace := "cmp-defaulting"
	if err := kubeClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	// The minimum a reader can write for a shared secret issuer. Every block absent here has to be
	// filled in by the schema, or the controller rejects what the API server just accepted.
	minimal := []byte(`
apiVersion: certmanager.misiektoja.github.io/v1alpha1
kind: CMPIssuer
metadata:
  name: minimal
spec:
  endpoint:
    url: http://cmp.example.com:8080/pkix/
  protocol:
    version: 2
    initialEnrollment: P10CR
    recipient: CN=Example CA,O=Example
    confirmation: Explicit
  protection:
    type: PasswordBasedMac
    passwordBasedMac:
      secretRef:
        name: cmp-credentials
  cmpTrust:
    caSecretRef:
      name: cmp-trust
      key: ca.crt
`)
	var object unstructured.Unstructured
	if err := yaml.Unmarshal(minimal, &object); err != nil {
		t.Fatalf("parse minimal issuer: %v", err)
	}
	object.SetNamespace(namespace)
	if err := kubeClient.Create(ctx, &object); err != nil {
		t.Fatalf("the minimal issuer is rejected by the API server: %v", err)
	}
	spec := loadDocumentedIssuerSpec(t, ctx, kubeClient, object)
	if _, err := validateSpec(spec); err != nil {
		t.Fatalf("the minimal issuer is accepted by the API server but rejected by the controller: %v", err)
	}
	algorithm := spec.Protection.PasswordBasedMac.Algorithm
	if algorithm.OWF != cmpv1alpha1.PasswordBasedMacOWFSHA256 || algorithm.MAC != cmpv1alpha1.PasswordBasedMacMACHMACSHA256 ||
		algorithm.IterationCount != cmpv1alpha1.PasswordBasedMacIterationCountDefault {
		t.Errorf("an omitted algorithm block was not defaulted, got %+v", algorithm)
	}
	if spec.Endpoint.Timeout.Duration == 0 || spec.Endpoint.MaxResponseSize == 0 {
		t.Errorf("an omitted endpoint bound was not defaulted, got timeout %v and maxResponseSize %d", spec.Endpoint.Timeout, spec.Endpoint.MaxResponseSize)
	}
	if spec.Policy.GrantedModifications != cmpv1alpha1.GrantedModificationsReject {
		t.Errorf("an omitted policy block was not defaulted, got %q", spec.Policy.GrantedModifications)
	}
	if spec.Transaction.MaximumPolls == 0 {
		t.Errorf("an omitted transaction block was not defaulted, got %+v", spec.Transaction)
	}
}
