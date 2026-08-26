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

// Package workflows guards the supply chain properties of the GitHub Actions workflows.
//
// These are conventions a reviewer has to remember on every workflow change, which is exactly the kind
// of thing that decays quietly. actionlint checks that a workflow is valid; nothing there checks that
// it is pinned, least privileged and free of interpolated shell.
package workflows

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// workflowDir is the workflow directory relative to this package.
const workflowDir = "../../.github/workflows"

var (
	// usesLine captures the indentation, the action reference and whatever follows it on the line.
	usesLine = regexp.MustCompile(`^(\s*)(?:-\s+)?uses:\s*(\S+)(.*)$`)
	// runLine captures the indentation and the remainder of a run key.
	runLine = regexp.MustCompile(`^(\s*)(?:-\s+)?run:(.*)$`)
	// shaPin matches an action reference pinned to a full 40 character commit SHA.
	shaPin = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)
	// versionComment matches the trailing comment naming the release the SHA belongs to.
	versionComment = regexp.MustCompile(`#\s*v\d`)
	// topLevelPermissions matches the permissions key at the root of a workflow document.
	topLevelPermissions = regexp.MustCompile(`(?m)^permissions:`)
)

// block is one run script together with the file line its run key sits on.
type block struct {
	firstLine int
	lines     []string
}

// workflowFiles returns every YAML workflow file, failing the test when the directory is empty.
func workflowFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("read %s: %v", workflowDir, err)
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		files = append(files, filepath.Join(workflowDir, name))
	}
	if len(files) == 0 {
		t.Fatalf("no workflow files under %s, so this test would pass without checking anything", workflowDir)
	}
	return files
}

// readLines returns the file split into lines, failing the test when it cannot be read.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Split(string(content), "\n")
}

// indentOf returns the number of leading spaces on a line.
func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// runBlocks returns every run script in the file, covering both inline scripts and block scalars.
func runBlocks(lines []string) []block {
	var blocks []block
	for i := 0; i < len(lines); i++ {
		match := runLine.FindStringSubmatch(lines[i])
		if match == nil {
			continue
		}
		current := block{firstLine: i + 1, lines: []string{lines[i]}}
		rest := strings.TrimSpace(match[2])
		// An inline script ends on its own line. Only a block scalar continues onto the next ones.
		if rest != "" && !strings.HasPrefix(rest, "|") && !strings.HasPrefix(rest, ">") {
			blocks = append(blocks, current)
			continue
		}
		indent := len(match[1])
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) != "" && indentOf(lines[j]) <= indent {
				break
			}
			current.lines = append(current.lines, lines[j])
			i = j
		}
		blocks = append(blocks, current)
	}
	return blocks
}

// TestWorkflowActionsArePinned requires every third-party action to be pinned to a commit SHA.
//
// A tag or a branch is mutable, so an upstream account compromise reaches this repository on the next
// run. The trailing version comment is what keeps a pinned SHA readable and reviewable.
func TestWorkflowActionsArePinned(t *testing.T) {
	for _, path := range workflowFiles(t) {
		for i, line := range readLines(t, path) {
			match := usesLine.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			ref, trailer := match[2], match[3]
			// A local action is part of this repository, and a container reference carries its own digest.
			if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
				continue
			}
			if !shaPin.MatchString(ref) {
				t.Errorf("%s:%d: %q is not pinned to a 40 character commit SHA", path, i+1, ref)
				continue
			}
			if !versionComment.MatchString(trailer) {
				t.Errorf("%s:%d: %q has no trailing version comment, for example `# v1.2.3`", path, i+1, ref)
			}
		}
	}
}

// TestWorkflowRunBlocksUseNoInterpolation requires run scripts to read values from env rather than
// interpolating them.
//
// GitHub substitutes an expression into the script text before the shell parses it, so a value
// carrying a quote or a newline becomes shell syntax. Passing it through env makes it data.
func TestWorkflowRunBlocksUseNoInterpolation(t *testing.T) {
	for _, path := range workflowFiles(t) {
		for _, script := range runBlocks(readLines(t, path)) {
			for offset, line := range script.lines {
				if !strings.Contains(line, "${{") {
					continue
				}
				t.Errorf("%s:%d: run block interpolates an expression, pass the value through env instead: %s",
					path, script.firstLine+offset, strings.TrimSpace(line))
			}
		}
	}
}

// TestWorkflowsDeclareTopLevelPermissions requires every workflow to set the token scope explicitly.
//
// Without the key the workflow inherits the repository default, which can be read and write on every
// scope. Declaring it at the root means a job added later starts from no permissions rather than all.
func TestWorkflowsDeclareTopLevelPermissions(t *testing.T) {
	for _, path := range workflowFiles(t) {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !topLevelPermissions.Match(content) {
			t.Errorf("%s: no top-level permissions key, so the workflow inherits the repository default", path)
		}
	}
}

// TestScorecardFollowsSuccessfulCodeQL keeps the published SAST result behind the analysis it measures.
func TestScorecardFollowsSuccessfulCodeQL(t *testing.T) {
	path := filepath.Join(workflowDir, "scorecard.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	workflow := string(content)
	required := []struct {
		text   string
		reason string
	}{
		{"workflow_run:", "Scorecard does not follow another workflow"},
		{"workflows: [CodeQL]", "Scorecard does not follow CodeQL"},
		{"types: [completed]", "Scorecard can start before CodeQL completes"},
		{"branches: [main]", "Scorecard follows CodeQL outside the default branch"},
		{"github.event.workflow_run.conclusion == 'success'", "Scorecard publishes after a failed CodeQL run"},
	}
	for _, check := range required {
		if !strings.Contains(workflow, check.text) {
			t.Errorf("%s: %s", path, check.reason)
		}
	}
	if strings.Contains(workflow, "\n  push:\n") {
		t.Errorf("%s: Scorecard still races CodeQL on a direct push trigger", path)
	}
}

// TestReleaseWorkflowBindsManualDispatchToTag keeps release artifacts tied to an existing tag on the default branch.
func TestReleaseWorkflowBindsManualDispatchToTag(t *testing.T) {
	path := filepath.Join(workflowDir, "release.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	workflow := string(content)
	required := []struct {
		text   string
		reason string
	}{
		{`ref: ${{ steps.release.outputs.version }}`, "checkout does not target the resolved release tag"},
		{"fetch-depth: 0", "checkout does not fetch the default branch history needed for the ancestry check"},
		{"git merge-base --is-ancestor", "the release tag is not checked against the default branch"},
		{"--verify-tag", "release publication can create a missing tag"},
		{"id: provenance", "the provenance bundle cannot be referenced by later release steps"},
		{"steps.provenance.outputs.bundle-path", "the signed provenance bundle is not staged"},
		{"cmp-issuer-${VERSION}-provenance.sigstore.json", "the signed provenance bundle is not a release asset"},
	}
	for _, check := range required {
		if !strings.Contains(workflow, check.text) {
			t.Errorf("%s: %s", path, check.reason)
		}
	}
	resolveAt := strings.Index(workflow, "- name: Resolve the release version")
	checkoutAt := strings.Index(workflow, "- name: Clone the code")
	if resolveAt < 0 || checkoutAt < 0 || resolveAt > checkoutAt {
		t.Errorf("%s: release version must be resolved before checkout", path)
	}
	// A release published by hand from the GitHub UI creates the tag, which starts this workflow. The
	// refusal has to come before the image is pushed, since a push cannot be withdrawn and leaves a
	// published release with no assets beside an image that is real.
	publishedGuardAt := strings.Index(workflow, "- name: Refuse to rebuild a release that is already published")
	pushAt := strings.Index(workflow, "- name: Build and push the multi architecture image")
	if publishedGuardAt < 0 || pushAt < 0 || publishedGuardAt > pushAt {
		t.Errorf("%s: an already published release must be refused before the image is pushed", path)
	}
	// Running before checkout leaves gh no git remote to infer the repository from, so without GH_REPO
	// every lookup fails and the check passes anything through.
	if publishedGuardAt >= 0 && !strings.Contains(workflow[publishedGuardAt:], "GH_REPO:") {
		t.Errorf("%s: the release lookup does not name the repository and cannot run before checkout", path)
	}
	loginAt := strings.Index(workflow, "- name: Log in to the container registry")
	if loginAt >= 0 && publishedGuardAt > loginAt {
		t.Errorf("%s: an already published release must be refused before the registry login", path)
	}
	unsafeReleaseCreate := `gh release create "$VERSION" --draft --notes-file dist/release-body.md ` +
		`--title "$VERSION" || true`
	if strings.Contains(workflow, unsafeReleaseCreate) {
		t.Errorf("%s: release creation errors are ignored", path)
	}
}

// TestReleaseWorkflowPublishesChecksumsAndArtifactProvenance keeps every downloadable payload verifiable.
func TestReleaseWorkflowPublishesChecksumsAndArtifactProvenance(t *testing.T) {
	path := filepath.Join(workflowDir, "release.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	workflow := string(content)
	required := []struct {
		text   string
		reason string
	}{
		{"make release-checksums", "the release does not build source archives and checksums"},
		{"_SHA256SUMS.txt", "the checksum manifest is not uploaded"},
		{"subject-path:", "release artifacts have no provenance subjects"},
		{"-source.zip", "the source ZIP is not uploaded or attested"},
		{"-source.tar.gz", "the source tar archive is not uploaded or attested"},
	}
	for _, check := range required {
		if !strings.Contains(workflow, check.text) {
			t.Errorf("%s: %s", path, check.reason)
		}
	}
	if strings.Count(workflow, "actions/attest-build-provenance@") < 2 {
		t.Errorf("%s: image and release artifacts do not each receive provenance", path)
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	for _, command := range []string{"git archive --format=zip", "git archive --format=tar.gz", "sha256sum"} {
		if !strings.Contains(string(makefile), command) {
			t.Errorf("Makefile: release-checksums is missing %q", command)
		}
	}
	checksumsAt := strings.Index(workflow, "- name: Build complete source archives and release checksums")
	attestationAt := strings.Index(workflow, "- name: Attest the release artifacts' build provenance")
	uploadAt := strings.Index(workflow, "- name: Publish the release assets")
	if checksumsAt < 0 || attestationAt < checksumsAt || uploadAt < attestationAt {
		t.Errorf("%s: archives, checksums, attestation and upload are not ordered safely", path)
	}
}

// TestPublishChartWorkflowPublishesArtifactHubMetadata keeps publisher verification beside the Helm index.
func TestPublishChartWorkflowPublishesArtifactHubMetadata(t *testing.T) {
	path := filepath.Join(workflowDir, "publish-chart.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	workflow := string(content)
	for _, required := range []string{
		"cp charts/artifacthub-repo.yml published/charts/artifacthub-repo.yml",
		"git -C published add charts/index.yaml charts/artifacthub-repo.yml .nojekyll",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("%s does not publish Artifact Hub metadata with the chart index: missing %q", path, required)
		}
	}
	metadata, err := os.ReadFile("../../charts/artifacthub-repo.yml")
	if err != nil {
		t.Fatalf("read Artifact Hub metadata: %v", err)
	}
	if !strings.Contains(string(metadata), "repositoryID: a74e0ed9-3729-471e-954f-6c44806d3fe4") {
		t.Error("Artifact Hub metadata does not identify the registered cmp-issuer repository")
	}
}
