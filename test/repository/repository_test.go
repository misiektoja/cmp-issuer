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

// Package repository guards the metadata and text conventions a complete source tree must carry.
package repository

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"sigs.k8s.io/yaml"
)

const (
	repositoryRoot   = "../.."
	editorConfigTrue = "true"
)

type citationAuthor struct {
	FamilyNames string `json:"family-names"`
	GivenNames  string `json:"given-names"`
	Alias       string `json:"alias"`
}

type citationMetadata struct {
	CFFVersion    string           `json:"cff-version"`
	Message       string           `json:"message"`
	Title         string           `json:"title"`
	Type          string           `json:"type"`
	Authors       []citationAuthor `json:"authors"`
	Version       string           `json:"version"`
	DateReleased  string           `json:"date-released"`
	License       string           `json:"license"`
	RepositoryURL string           `json:"repository-code"`
}

type preCommitHook struct {
	ID string `json:"id"`
}

type preCommitRepository struct {
	Repository string          `json:"repo"`
	Revision   string          `json:"rev"`
	Hooks      []preCommitHook `json:"hooks"`
}

type preCommitConfiguration struct {
	Repositories []preCommitRepository `json:"repos"`
}

// readRepositoryFile reads a repository asset and fails the current test when it is unavailable
func readRepositoryFile(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repositoryRoot, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return content
}

// parseEditorConfiguration reads EditorConfig sections into key-value maps
func parseEditorConfiguration(t *testing.T) map[string]map[string]string {
	t.Helper()
	sections := map[string]map[string]string{"": {}}
	current := ""
	scanner := bufio.NewScanner(bytes.NewReader(readRepositoryFile(t, ".editorconfig")))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			sections[current] = map[string]string{}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("unparseable .editorconfig line %q", line)
		}
		sections[current][strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan .editorconfig: %v", err)
	}
	return sections
}

// trackedRepositoryFiles lists every path Git includes in the source tree
func trackedRepositoryFiles(t *testing.T) []string {
	t.Helper()
	command := exec.Command("git", "ls-files", "-z")
	command.Dir = repositoryRoot
	output, err := command.Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	trimmed := bytes.TrimSuffix(output, []byte{0})
	if len(trimmed) == 0 {
		return nil
	}
	parts := bytes.Split(trimmed, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		files = append(files, string(part))
	}
	return files
}

// isBinaryAsset reports whether Git attributes deliberately classify the image as binary
func isBinaryAsset(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".gif", ".jpeg", ".jpg", ".png", ".svg":
		return true
	default:
		return false
	}
}

// TestRepositoryGovernanceDocumentsExist keeps every contributor-facing repository policy available
func TestRepositoryGovernanceDocumentsExist(t *testing.T) {
	assets := []string{
		"SECURITY.md",
		"SUPPORT.md",
		"CONTRIBUTING.md",
		"CODE_OF_CONDUCT.md",
		"THIRD_PARTY_NOTICES.md",
		"CITATION.cff",
		"LICENSE",
		".github/pull_request_template.md",
	}
	for _, name := range assets {
		information, err := os.Stat(filepath.Join(repositoryRoot, name))
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if information.Size() <= 200 {
			t.Errorf("%s is only %d bytes and appears empty", name, information.Size())
		}
	}
}

// TestCitationMetadataDescribesThisProject keeps GitHub citation metadata parseable and project-specific
func TestCitationMetadataDescribesThisProject(t *testing.T) {
	var citation citationMetadata
	if err := yaml.Unmarshal(readRepositoryFile(t, "CITATION.cff"), &citation); err != nil {
		t.Fatalf("parse CITATION.cff: %v", err)
	}
	if citation.CFFVersion != "1.2.0" || citation.Type != "software" || citation.Title != "cmp-issuer" {
		t.Errorf("unexpected citation identity: %+v", citation)
	}
	if citation.Message == "" {
		t.Error("citation message is empty")
	}
	if citation.License != "Apache-2.0" {
		t.Errorf("citation license = %q, want Apache-2.0", citation.License)
	}
	if citation.RepositoryURL != "https://github.com/misiektoja/cmp-issuer" {
		t.Errorf("citation repository = %q", citation.RepositoryURL)
	}
	if len(citation.Authors) != 1 {
		t.Fatalf("citation authors = %d, want 1", len(citation.Authors))
	}
	author := citation.Authors[0]
	if author.GivenNames != "Michal" || author.FamilyNames != "Szymanski" || author.Alias != "misiektoja" {
		t.Errorf("unexpected citation author: %+v", author)
	}
}

// TestCitationTracksNewestReleasedVersion ties the citation to the newest dated release notes section
func TestCitationTracksNewestReleasedVersion(t *testing.T) {
	var citation citationMetadata
	if err := yaml.Unmarshal(readRepositoryFile(t, "CITATION.cff"), &citation); err != nil {
		t.Fatalf("parse CITATION.cff: %v", err)
	}
	heading := regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - ([0-9]{1,2} [A-Z][a-z]{2} [0-9]{4})$`)
	released := heading.FindSubmatch(readRepositoryFile(t, "RELEASE_NOTES.md"))
	if released == nil {
		t.Fatal("RELEASE_NOTES.md has no dated release section")
	}
	releaseDate, err := time.Parse("2 Jan 2006", string(released[2]))
	if err != nil {
		t.Fatalf("parse release date: %v", err)
	}
	if citation.Version != string(released[1]) {
		t.Errorf("citation version = %q, newest released version = %q", citation.Version, released[1])
	}
	if citation.DateReleased != releaseDate.Format(time.DateOnly) {
		t.Errorf("citation date = %q, newest release date = %q", citation.DateReleased, releaseDate.Format(time.DateOnly))
	}
}

// TestEditorConfigurationDeclaresRepositoryStyle keeps the shared settings aligned with measured files
func TestEditorConfigurationDeclaresRepositoryStyle(t *testing.T) {
	sections := parseEditorConfiguration(t)
	global := sections["*"]
	wants := map[string]string{
		"charset":                  "utf-8",
		"end_of_line":              "lf",
		"indent_style":             "space",
		"indent_size":              "2",
		"insert_final_newline":     editorConfigTrue,
		"trim_trailing_whitespace": editorConfigTrue,
	}
	if sections[""]["root"] != editorConfigTrue {
		t.Errorf("EditorConfig root = %q, want true", sections[""]["root"])
	}
	for key, want := range wants {
		if global[key] != want {
			t.Errorf("EditorConfig %s = %q, want %q", key, global[key], want)
		}
	}
	for _, section := range []string{"*.go", "go.mod", "Makefile"} {
		if sections[section]["indent_style"] != "tab" || sections[section]["indent_size"] != "tab" {
			t.Errorf("EditorConfig section %q does not require tabs: %v", section, sections[section])
		}
	}
	if sections["*.go"]["tab_width"] != "8" || sections["go.mod"]["tab_width"] != "8" {
		t.Error("Go tab width must be eight columns")
	}
	if sections["*.md"]["trim_trailing_whitespace"] != "false" {
		t.Error("Markdown must preserve meaningful trailing spaces")
	}
	license := sections["LICENSE"]
	if license["insert_final_newline"] != "unset" || license["trim_trailing_whitespace"] != "unset" {
		t.Error("LICENSE must remain exempt from rewriting")
	}
}

// TestTrackedTextFilesObeyWhitespacePolicy checks the repository independently of editor support
func TestTrackedTextFilesObeyWhitespacePolicy(t *testing.T) {
	var offenders []string
	for _, name := range trackedRepositoryFiles(t) {
		path := filepath.Join(repositoryRoot, name)
		information, err := os.Stat(path)
		if err != nil || !information.Mode().IsRegular() || isBinaryAsset(name) {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			offenders = append(offenders, name+": unreadable")
			continue
		}
		if !utf8.Valid(content) {
			offenders = append(offenders, name+": not UTF-8")
		}
		if bytes.Contains(content, []byte("\r\n")) {
			offenders = append(offenders, name+": CRLF line ending")
		}
		if len(content) > 0 && content[len(content)-1] != '\n' {
			offenders = append(offenders, name+": missing final newline")
		}
		if name == "LICENSE" || strings.EqualFold(filepath.Ext(name), ".md") {
			continue
		}
		for lineNumber, line := range bytes.Split(content, []byte("\n")) {
			if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
				offenders = append(offenders, name+":"+strconv.Itoa(lineNumber+1)+": trailing whitespace")
			}
		}
	}
	if len(offenders) > 0 {
		t.Errorf("tracked text whitespace violations:\n%s", strings.Join(offenders, "\n"))
	}
}

// TestLineEndingAndBinaryPoliciesAreDeclared keeps archive contents normalized without hiding files
func TestLineEndingAndBinaryPoliciesAreDeclared(t *testing.T) {
	attributes := string(readRepositoryFile(t, ".gitattributes"))
	declarations := []string{
		"* text=auto eol=lf",
		"*.png binary",
		"*.jpg binary",
		"*.jpeg binary",
		"*.gif binary",
		"*.svg binary",
	}
	for _, declaration := range declarations {
		if !strings.Contains(attributes, declaration) {
			t.Errorf(".gitattributes is missing %q", declaration)
		}
	}
	if regexp.MustCompile(`(?m)^[^#\n]*export-ignore`).MatchString(attributes) {
		t.Error(".gitattributes excludes files from release source archives")
	}
}

// TestLocalHooksStayToolchainFreeAndCIRunsLint keeps fast hooks separate from authoritative Go checks
func TestLocalHooksStayToolchainFreeAndCIRunsLint(t *testing.T) {
	var configuration preCommitConfiguration
	if err := yaml.Unmarshal(readRepositoryFile(t, ".pre-commit-config.yaml"), &configuration); err != nil {
		t.Fatalf("parse .pre-commit-config.yaml: %v", err)
	}
	if len(configuration.Repositories) != 1 {
		t.Fatalf("pre-commit repositories = %d, want one toolchain-free hook repository", len(configuration.Repositories))
	}
	repository := configuration.Repositories[0]
	if repository.Repository != "https://github.com/pre-commit/pre-commit-hooks" || repository.Revision != "v6.0.0" {
		t.Errorf("unexpected pre-commit source: %+v", repository)
	}
	hooks := map[string]bool{}
	for _, hook := range repository.Hooks {
		hooks[hook.ID] = true
	}
	requiredHooks := []string{
		"trailing-whitespace",
		"end-of-file-fixer",
		"mixed-line-ending",
		"check-yaml",
		"check-toml",
		"check-merge-conflict",
		"check-added-large-files",
		"detect-private-key",
	}
	for _, required := range requiredHooks {
		if !hooks[required] {
			t.Errorf("pre-commit is missing %s", required)
		}
	}
	makefile := string(readRepositoryFile(t, "Makefile"))
	if !regexp.MustCompile(`(?m)^GOLANGCI_LINT_VERSION \?= v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(makefile) {
		t.Error("Makefile does not pin golangci-lint")
	}
	lintWorkflow := string(readRepositoryFile(t, ".github/workflows/lint.yml"))
	if !strings.Contains(lintWorkflow, "run: make lint") {
		t.Error("lint workflow does not run the pinned Go linter")
	}
}

// TestSupportDocumentRoutesEveryRequestType keeps help and disclosure channels discoverable
func TestSupportDocumentRoutesEveryRequestType(t *testing.T) {
	support := string(readRepositoryFile(t, "SUPPORT.md"))
	for _, destination := range []string{
		"https://github.com/misiektoja/cmp-issuer/discussions",
		"https://github.com/misiektoja/cmp-issuer/issues/new?template=bug_report.yml",
		"https://github.com/misiektoja/cmp-issuer/issues/new?template=feature_request.yml",
		"https://github.com/misiektoja/cmp-issuer/security/advisories/new",
	} {
		if !strings.Contains(support, destination) {
			t.Errorf("SUPPORT.md is missing %s", destination)
		}
	}
	diagnostics := []string{
		"/manager --version",
		"kubectl describe cmpissuer",
		"kubectl describe certificaterequest",
		"kubectl get cmptransactions",
		"kubectl logs",
	}
	for _, diagnostic := range diagnostics {
		if !strings.Contains(support, diagnostic) {
			t.Errorf("SUPPORT.md is missing diagnostic %q", diagnostic)
		}
	}
}
