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

package repository

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	contributorAuthor  = "Contributor <contributor@example.com>"
	reviewerAuthor     = "Reviewer <reviewer@example.com>"
	dependabotAuthor   = "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
	contributorSignOff = "Signed-off-by: Contributor <contributor@example.com>"
	dcoBaseTag         = "base"
	dcoFailureMarker   = "no Signed-off-by trailer"
)

// dcoCommit is one commit created in a DCO fixture repository
type dcoCommit struct {
	author  string
	message string
}

// dcoRepository is a throwaway Git repository isolated from the user and system Git configuration
type dcoRepository struct {
	t   *testing.T
	dir string
	env []string
}

// newDCORepository creates a repository whose base tag marks a signed-off starting commit
func newDCORepository(t *testing.T) *dcoRepository {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is unavailable: %v", err)
	}
	env := []string{
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Contributor",
		"GIT_AUTHOR_EMAIL=contributor@example.com",
		"GIT_COMMITTER_NAME=Committer",
		"GIT_COMMITTER_EMAIL=committer@example.com",
	}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GIT_") {
			env = append(env, entry)
		}
	}
	repository := &dcoRepository{t: t, dir: t.TempDir(), env: env}
	repository.git("", "init", "-q", "-b", "dev")
	repository.commit(dcoCommit{author: contributorAuthor, message: "chore: start\n\n" + contributorSignOff})
	repository.git("", "tag", dcoBaseTag)
	return repository
}

// git runs a Git command in the fixture repository and fails the test when it fails
func (r *dcoRepository) git(stdin string, args ...string) {
	r.t.Helper()
	command := exec.Command("git", args...)
	command.Dir = r.dir
	command.Env = r.env
	command.Stdin = strings.NewReader(stdin)
	if output, err := command.CombinedOutput(); err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

// commit records an empty commit with the given author and message
func (r *dcoRepository) commit(commit dcoCommit) {
	r.t.Helper()
	r.git(commit.message, "commit", "-q", "--allow-empty", "--author", commit.author, "-F", "-")
}

// checkDCO runs the sign-off check with the given arguments and returns its output and exit code
func (r *dcoRepository) checkDCO(args ...string) (string, int) {
	r.t.Helper()
	script, err := filepath.Abs(filepath.Join(repositoryRoot, "hack", "check-dco.sh"))
	if err != nil {
		r.t.Fatalf("resolve the DCO script: %v", err)
	}
	command := exec.Command(script, args...)
	command.Dir = r.dir
	command.Env = r.env
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(output), 0
	case errors.As(err, &exitErr):
		return string(output), exitErr.ExitCode()
	default:
		r.t.Fatalf("run %s: %v", script, err)
		return "", -1
	}
}

// TestDCOCheckRequiresAuthorSignOff covers which sign-off trailers certify a commit
func TestDCOCheckRequiresAuthorSignOff(t *testing.T) {
	cases := []struct {
		name    string
		commits []dcoCommit
		failing []string
	}{
		{
			name:    "author sign-off",
			commits: []dcoCommit{{author: contributorAuthor, message: "feat: signed\n\n" + contributorSignOff}},
		},
		{
			name: "sign-off email differs only in case",
			commits: []dcoCommit{{
				author:  contributorAuthor,
				message: "feat: mixed case\n\nSigned-off-by: Contributor <Contributor@Example.COM>",
			}},
		},
		{
			name: "author among several sign-offs",
			commits: []dcoCommit{{
				author:  contributorAuthor,
				message: "feat: relayed\n\nSigned-off-by: " + reviewerAuthor + "\n" + contributorSignOff,
			}},
		},
		{
			name:    "missing sign-off",
			commits: []dcoCommit{{author: contributorAuthor, message: "feat: unsigned"}},
			failing: []string{"feat: unsigned"},
		},
		{
			name: "sign-off by someone else",
			commits: []dcoCommit{{
				author:  contributorAuthor,
				message: "feat: foreign\n\nSigned-off-by: " + reviewerAuthor,
			}},
			failing: []string{"feat: foreign"},
		},
		{
			name: "sign-off outside the trailer block",
			commits: []dcoCommit{{
				author:  contributorAuthor,
				message: "feat: buried\n\n" + contributorSignOff + "\n\nA closing paragraph after the line.",
			}},
			failing: []string{"feat: buried"},
		},
		{
			name: "Dependabot sign-off address",
			commits: []dcoCommit{{
				author:  dependabotAuthor,
				message: "build(deps): bump\n\nSigned-off-by: dependabot[bot] <support@github.com>",
			}},
		},
		{
			name:    "Dependabot without sign-off",
			commits: []dcoCommit{{author: dependabotAuthor, message: "build(deps): unsigned bump"}},
			failing: []string{"build(deps): unsigned bump"},
		},
		{
			name: "only the unsigned commit is reported",
			commits: []dcoCommit{
				{author: contributorAuthor, message: "feat: first\n\n" + contributorSignOff},
				{author: contributorAuthor, message: "feat: second"},
			},
			failing: []string{"feat: second"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repository := newDCORepository(t)
			for _, commit := range tc.commits {
				repository.commit(commit)
			}
			output, code := repository.checkDCO(dcoBaseTag)
			wantCode := 0
			if len(tc.failing) > 0 {
				wantCode = 1
			}
			if code != wantCode {
				t.Fatalf("exit code %d, want %d\n%s", code, wantCode, output)
			}
			if reported := strings.Count(output, dcoFailureMarker); reported != len(tc.failing) {
				t.Errorf("reported %d commits, want %d\n%s", reported, len(tc.failing), output)
			}
			for _, subject := range tc.failing {
				if !strings.Contains(output, subject+": "+dcoFailureMarker) {
					t.Errorf("output does not name %q\n%s", subject, output)
				}
			}
		})
	}
}

// TestDCOCheckSkipsMergeCommits keeps merge commits out of the sign-off requirement
func TestDCOCheckSkipsMergeCommits(t *testing.T) {
	repository := newDCORepository(t)
	repository.git("", "checkout", "-q", "-b", "topic")
	repository.commit(dcoCommit{author: contributorAuthor, message: "feat: topic\n\n" + contributorSignOff})
	repository.git("", "checkout", "-q", "dev")
	repository.commit(dcoCommit{author: contributorAuthor, message: "feat: mainline\n\n" + contributorSignOff})
	repository.git("", "merge", "-q", "--no-ff", "-m", "Merge branch topic", "topic")
	output, code := repository.checkDCO(dcoBaseTag)
	if code != 0 || !strings.Contains(output, "(2 checked)") {
		t.Fatalf("exit code %d, want 0 with two commits checked\n%s", code, output)
	}
}

// TestDCOCheckRejectsInvalidArguments keeps a mistyped range from passing as an empty one
func TestDCOCheckRejectsInvalidArguments(t *testing.T) {
	repository := newDCORepository(t)
	for _, args := range [][]string{nil, {"missing-ref"}, {dcoBaseTag, "missing-ref"}, {dcoBaseTag, "HEAD", "extra"}} {
		if output, code := repository.checkDCO(args...); code != 2 {
			t.Errorf("arguments %q: exit code %d, want 2\n%s", args, code, output)
		}
	}
}
