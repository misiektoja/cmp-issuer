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

// Package workflows checks the security and publication rules of GitHub Actions workflows.
package workflows

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

const workflowDir = "../../.github/workflows"

var shaPin = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)
var versionComment = regexp.MustCompile(`#\s*v\d`)

type workflow struct {
	On          map[string]yaml.Node `yaml:"on"`
	Permissions yaml.Node
	Jobs        map[string]workflowJob
}

type workflowTrigger struct {
	Workflows []string
	Types     []string
	Branches  []string
}

type workflowJob struct {
	If    string
	Uses  yaml.Node
	Steps []workflowStep
}

type workflowStep struct {
	ID   string
	Uses yaml.Node
	Run  yaml.Node
	With map[string]string
	Env  map[string]string
}

// readWorkflow decodes one workflow and fails the test if it cannot be read or parsed.
func readWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(workflowDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var result workflow
	if err := yaml.Unmarshal(content, &result); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return result
}

// TestWorkflowSecurity checks action pins, explicit permissions and shell interpolation.
func TestWorkflowSecurity(t *testing.T) {
	files, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, file := range files {
		name := file.Name()
		if file.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		count++
		t.Run(name, func(t *testing.T) {
			document := readWorkflow(t, name)
			if document.Permissions.Kind == 0 {
				t.Error("workflow must declare top-level token permissions")
			}
			for _, job := range document.Jobs {
				checkActionPin(t, job.Uses)
				for _, step := range job.Steps {
					checkActionPin(t, step.Uses)
					// Expressions become shell syntax before execution, while env values remain data.
					if strings.Contains(step.Run.Value, "${{") {
						t.Errorf("line %d: pass expressions through env instead of interpolating shell", step.Run.Line)
					}
				}
			}
		})
	}
	if count == 0 {
		t.Fatal("no workflows found")
	}
}

// checkActionPin requires immutable third-party action references and a readable version comment.
func checkActionPin(t *testing.T, node yaml.Node) {
	t.Helper()
	ref := node.Value
	if ref == "" || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
		return
	}
	if !shaPin.MatchString(ref) {
		t.Errorf("line %d: action %q must use a full commit SHA", node.Line, ref)
	}
	if !versionComment.MatchString(node.LineComment) {
		t.Errorf("line %d: action %q needs a version comment", node.Line, ref)
	}
}

// TestScorecardFollowsSuccessfulCodeQL keeps Scorecard behind the analysis it measures.
func TestScorecardFollowsSuccessfulCodeQL(t *testing.T) {
	document := readWorkflow(t, "scorecard.yml")
	triggerNode, found := document.On["workflow_run"]
	var trigger workflowTrigger
	if err := triggerNode.Decode(&trigger); err != nil {
		t.Fatal(err)
	}
	if !found || !slices.Equal(trigger.Workflows, []string{"CodeQL"}) ||
		!slices.Equal(trigger.Types, []string{"completed"}) || !slices.Equal(trigger.Branches, []string{"main"}) {
		t.Errorf("unexpected CodeQL completion trigger: %+v", trigger)
	}
	if _, found := document.On["push"]; found {
		t.Error("a direct push trigger races CodeQL")
	}
	if !strings.Contains(document.Jobs["analyze"].If, "github.event.workflow_run.conclusion == 'success'") {
		t.Error("Scorecard must require a successful CodeQL run")
	}
}

// stepIndex requires exactly one match by ID, action or command.
func stepIndex(t *testing.T, steps []workflowStep, matches func(workflowStep) bool) int {
	t.Helper()
	index := -1
	for i, step := range steps {
		if !matches(step) {
			continue
		}
		if index != -1 {
			t.Fatal("release step selector matched more than one step")
		}
		index = i
	}
	if index == -1 {
		t.Fatal("required release step is missing")
	}
	return index
}

// actionStep finds the unique step that uses the requested action.
func actionStep(t *testing.T, steps []workflowStep, action string) int {
	t.Helper()
	return stepIndex(t, steps, func(step workflowStep) bool { return strings.HasPrefix(step.Uses.Value, action+"@") })
}

// commandStep finds the unique step that runs the requested command.
func commandStep(t *testing.T, steps []workflowStep, command string) int {
	t.Helper()
	return stepIndex(t, steps, func(step workflowStep) bool { return strings.Contains(step.Run.Value, command) })
}

// TestReleaseWorkflowBindsManualDispatchToTag checks tag selection and guards before publication.
func TestReleaseWorkflowBindsManualDispatchToTag(t *testing.T) {
	steps := readWorkflow(t, "release.yml").Jobs["publish"].Steps
	resolve := stepIndex(t, steps, func(step workflowStep) bool { return step.ID == "release" })
	checkout := actionStep(t, steps, "actions/checkout")
	if steps[checkout].With["ref"] != "${{ steps.release.outputs.version }}" ||
		steps[checkout].With["fetch-depth"] != "0" {
		t.Error("checkout must use the resolved tag and fetch its ancestry")
	}
	if resolve >= checkout {
		t.Error("resolve the tag before checkout")
	}
	guard := commandStep(t, steps, "gh release view")
	login := commandStep(t, steps, "docker login")
	push := commandStep(t, steps, "make docker-release")
	ancestry := commandStep(t, steps, "git merge-base --is-ancestor")
	if guard >= checkout || guard >= login || guard >= push || ancestry <= checkout || ancestry >= push {
		t.Error("check publication state before checkout and registry access, then verify tag ancestry before push")
	}
	if steps[guard].Env["GH_REPO"] != "${{ github.repository }}" {
		t.Error("release lookup before checkout must name the repository")
	}
	publish := commandStep(t, steps, "gh release create")
	for line := range strings.SplitSeq(steps[publish].Run.Value, "\n") {
		if !strings.Contains(line, "gh release create") && !strings.Contains(line, "gh release edit") {
			continue
		}
		if !strings.Contains(line, "--verify-tag") || strings.Contains(line, "|| true") {
			t.Error("release publication must verify the tag and propagate errors")
		}
	}
	provenance := stepIndex(t, steps, func(step workflowStep) bool { return step.ID == "provenance" })
	if !strings.HasPrefix(steps[provenance].Uses.Value, "actions/attest-build-provenance@") {
		t.Error("image provenance step must create an attestation")
	}
	stage := stepIndex(t, steps, func(step workflowStep) bool { return step.Env["PROVENANCE_BUNDLE"] != "" })
	if steps[stage].Env["PROVENANCE_BUNDLE"] != "${{ steps.provenance.outputs.bundle-path }}" || stage <= provenance {
		t.Error("stage the signed image provenance after attestation")
	}
	if !strings.Contains(steps[stage].Run.Value, "cmp-issuer-${VERSION}-provenance.sigstore.json") {
		t.Error("stage the image provenance under its release asset name")
	}
}

// TestReleaseWorkflowPublishesChecksumsAndArtifactProvenance checks payloads and publication order.
func TestReleaseWorkflowPublishesChecksumsAndArtifactProvenance(t *testing.T) {
	steps := readWorkflow(t, "release.yml").Jobs["publish"].Steps
	checksums := commandStep(t, steps, "make release-checksums")
	attestation := stepIndex(t, steps, func(step workflowStep) bool { return step.ID == "artifacts" })
	upload := commandStep(t, steps, "gh release upload")
	if checksums >= attestation || attestation >= upload {
		t.Error("build checksums before attestation and attest before upload")
	}
	if !strings.HasPrefix(steps[attestation].Uses.Value, "actions/attest-build-provenance@") {
		t.Error("release payloads need their own provenance")
	}
	for _, suffix := range []string{"_SHA256SUMS.txt", "-source.zip", "-source.tar.gz"} {
		if !strings.Contains(steps[attestation].With["subject-path"], suffix) ||
			!strings.Contains(steps[upload].Run.Value, suffix) {
			t.Errorf("%s must be uploaded and attested", suffix)
		}
	}
	if !strings.Contains(steps[upload].Run.Value, "-provenance.sigstore.json") {
		t.Error("upload the signed image provenance bundle")
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"git archive --format=zip", "git archive --format=tar.gz", "sha256sum"} {
		if !strings.Contains(string(makefile), command) {
			t.Errorf("Makefile: release-checksums is missing %q", command)
		}
	}
}

// TestPublishChartWorkflowPublishesArtifactHubMetadata checks metadata publication beside the chart index.
func TestPublishChartWorkflowPublishesArtifactHubMetadata(t *testing.T) {
	document := readWorkflow(t, "publish-chart.yml")
	var scripts strings.Builder
	for _, job := range document.Jobs {
		for _, step := range job.Steps {
			scripts.WriteString(step.Run.Value)
			scripts.WriteByte('\n')
		}
	}
	for _, required := range []string{
		"cp charts/artifacthub-repo.yml published/charts/artifacthub-repo.yml",
		"git -C published add charts/index.yaml charts/artifacthub-repo.yml .nojekyll",
	} {
		if !strings.Contains(scripts.String(), required) {
			t.Errorf("chart publication is missing %q", required)
		}
	}
	content, err := os.ReadFile("../../charts/artifacthub-repo.yml")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		RepositoryID string `yaml:"repositoryID"`
	}
	if err := yaml.Unmarshal(content, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.RepositoryID != "a74e0ed9-3729-471e-954f-6c44806d3fe4" {
		t.Error("Artifact Hub metadata must identify the registered repository")
	}
}
