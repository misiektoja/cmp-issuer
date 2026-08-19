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

package version

import (
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/misiektoja/cmp-issuer/internal/logging"
)

const (
	testVersion     = "v0.1.0"
	testCommit      = "1081fb2ff26a8b021c6d63e72a8f7ce2a8771a0d"
	testShortCommit = "1081fb2ff26a"
	testDate        = "2026-08-19T01:15:49Z"
	testImage       = "ghcr.io/misiektoja/cmp-issuer:v0.1.0"
	testChart       = "cmp-issuer-0.1.0"
	testRelease     = "cmp-issuer"
	testGoVersion   = "go1.26.6"
	testPlatform    = "linux/amd64"
)

// identityKeys are the fields the identity renders, in the order it renders them.
var identityKeys = []string{
	versionKey, commitKey, dateKey, goVersionKey, platformKey, imageKey, chartKey, releaseKey,
}

// noBuildInfo stands in for a binary carrying no embedded build metadata.
func noBuildInfo() (*debug.BuildInfo, bool) { return nil, false }

// embeddedBuildInfo returns a reader of fixed embedded build metadata.
func embeddedBuildInfo(build *debug.BuildInfo) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) { return build, true }
}

// noEnvironment stands in for a manager started with none of the install variables set.
func noEnvironment(string) (string, bool) { return "", false }

// environment returns a lookup over a fixed set of variables.
func environment(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

// stamp replaces the linker-stamped values for one test and restores them afterwards.
func stamp(t *testing.T, stampedVersion, stampedCommit, stampedDate, stampedImage string) {
	t.Helper()
	previous := [4]string{version, gitCommit, buildDate, image}
	t.Cleanup(func() {
		version, gitCommit, buildDate, image = previous[0], previous[1], previous[2], previous[3]
	})
	version, gitCommit, buildDate, image = stampedVersion, stampedCommit, stampedDate, stampedImage
}

// keysOf returns the keys of a rendered key value slice, failing the test if the pairs are unbalanced.
func keysOf(t *testing.T, pairs []any) []string {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatalf("expected balanced key value pairs, got %d entries", len(pairs))
	}
	keys := make([]string, 0, len(pairs)/2)
	for index := 0; index < len(pairs); index += 2 {
		key, ok := pairs[index].(string)
		if !ok {
			t.Fatalf("expected a string key at position %d, got %v", index, pairs[index])
		}
		keys = append(keys, key)
	}
	return keys
}

// TestResolveReportsTheStampedIdentity verifies a release build names the release, commit and image it came from.
func TestResolveReportsTheStampedIdentity(t *testing.T) {
	stamp(t, testVersion, testCommit, testDate, testImage)
	info := resolve(noBuildInfo, noEnvironment)
	if info.Version != testVersion {
		t.Fatalf("expected the stamped version, got %q", info.Version)
	}
	if info.GitCommit != testShortCommit {
		t.Fatalf("expected the commit shortened to %d characters, got %q", commitLength, info.GitCommit)
	}
	if info.BuildDate != testDate {
		t.Fatalf("expected the stamped build date, got %q", info.BuildDate)
	}
	if info.Image != testImage {
		t.Fatalf("expected the stamped image, got %q", info.Image)
	}
	if info.GoVersion != runtime.Version() || info.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("expected the runtime to report itself, got %q and %q", info.GoVersion, info.Platform)
	}
}

// TestResolveFallsBackToEmbeddedBuildMetadata verifies an unstamped build still names the tree it came from.
func TestResolveFallsBackToEmbeddedBuildMetadata(t *testing.T) {
	stamp(t, developmentVersion, "", "", "")
	build := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.1.1"},
		Settings: []debug.BuildSetting{
			{Key: revisionSetting, Value: testCommit},
			{Key: revisionTimeSetting, Value: testDate},
			{Key: modifiedSetting, Value: "true"},
		},
	}
	info := resolve(embeddedBuildInfo(build), noEnvironment)
	if info.Version != "v0.1.1" {
		t.Fatalf("expected the module version, got %q", info.Version)
	}
	if info.GitCommit != testShortCommit+"-dirty" {
		t.Fatalf("expected the revision marked as modified, got %q", info.GitCommit)
	}
	if info.BuildDate != testDate {
		t.Fatalf("expected the commit time, got %q", info.BuildDate)
	}
}

// TestResolveKeepsTheStampOverEmbeddedMetadata verifies a release build is not renamed by the module version.
func TestResolveKeepsTheStampOverEmbeddedMetadata(t *testing.T) {
	stamp(t, testVersion, testCommit, testDate, "")
	build := &debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: revisionSetting, Value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			{Key: revisionTimeSetting, Value: "2020-01-01T00:00:00Z"},
		},
	}
	info := resolve(embeddedBuildInfo(build), noEnvironment)
	if info.Version != testVersion || info.GitCommit != testShortCommit || info.BuildDate != testDate {
		t.Fatalf("expected the stamped identity to win, got %+v", info)
	}
}

// TestResolveIgnoresTheDevelopmentModuleVersion verifies a build outside a module release stays named development.
func TestResolveIgnoresTheDevelopmentModuleVersion(t *testing.T) {
	stamp(t, developmentVersion, "", "", "")
	build := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}
	info := resolve(embeddedBuildInfo(build), noEnvironment)
	if info.Version != developmentVersion {
		t.Fatalf("expected %q, got %q", developmentVersion, info.Version)
	}
}

// TestResolveReadsTheInstallIdentityFromTheEnvironment verifies the chart names the install the build cannot know.
func TestResolveReadsTheInstallIdentityFromTheEnvironment(t *testing.T) {
	stamp(t, testVersion, "", "", testImage)
	mirrored := "registry.example.test/mirror/cmp-issuer:v0.1.0"
	info := resolve(noBuildInfo, environment(map[string]string{
		ImageEnvVar:   mirrored,
		ChartEnvVar:   testChart,
		ReleaseEnvVar: testRelease,
	}))
	if info.Image != mirrored {
		t.Fatalf("expected the deployed image to override the stamped one, got %q", info.Image)
	}
	if info.Chart != testChart || info.Release != testRelease {
		t.Fatalf("expected the chart and release to be reported, got %q and %q", info.Chart, info.Release)
	}
}

// TestResolveKeepsTheStampedImageWhenTheEnvironmentIsEmpty verifies an empty variable does not erase the build value.
func TestResolveKeepsTheStampedImageWhenTheEnvironmentIsEmpty(t *testing.T) {
	stamp(t, testVersion, "", "", testImage)
	info := resolve(noBuildInfo, environment(map[string]string{ImageEnvVar: ""}))
	if info.Image != testImage {
		t.Fatalf("expected the stamped image to survive, got %q", info.Image)
	}
}

// TestResolveBoundsTheInstallIdentity verifies a deployment cannot forge or flood a log line through these variables.
func TestResolveBoundsTheInstallIdentity(t *testing.T) {
	stamp(t, testVersion, "", "", "")
	info := resolve(noBuildInfo, environment(map[string]string{
		ImageEnvVar: "forged\n{\"level\":\"info\",\"msg\":\"issued\"}",
		ChartEnvVar: strings.Repeat("a", 10*logging.MaxTextLength),
	}))
	if strings.ContainsAny(info.Image, "\n\r") {
		t.Fatalf("expected line breaks to be replaced, got %q", info.Image)
	}
	if !strings.HasSuffix(info.Chart, "...(truncated)") {
		t.Fatalf("expected a long value to be truncated, got %d characters", len(info.Chart))
	}
}

// TestResolveNamesAnUnknownBuildDevelopment verifies an empty stamp never produces a blank version.
func TestResolveNamesAnUnknownBuildDevelopment(t *testing.T) {
	stamp(t, "", "", "", "")
	if info := resolve(noBuildInfo, noEnvironment); info.Version != developmentVersion {
		t.Fatalf("expected %q, got %q", developmentVersion, info.Version)
	}
}

// TestKeysAndValuesReportsEveryKnownFieldInOrder verifies nothing the manager knows is dropped or reordered.
func TestKeysAndValuesReportsEveryKnownFieldInOrder(t *testing.T) {
	info := Info{
		Version: testVersion, GitCommit: testShortCommit, BuildDate: testDate,
		GoVersion: testGoVersion, Platform: testPlatform,
		Image: testImage, Chart: testChart, Release: testRelease,
	}
	pairs := info.KeysAndValues()
	if keys := keysOf(t, pairs); !slices.Equal(keys, identityKeys) {
		t.Fatalf("expected %v, got %v", identityKeys, keys)
	}
	if pairs[1] != testVersion || pairs[len(pairs)-1] != testRelease {
		t.Fatalf("expected each key to carry its own value, got %v", pairs)
	}
}

// TestKeysAndValuesOmitsWhatTheBuildDoesNotKnow verifies the log line carries no empty fields.
func TestKeysAndValuesOmitsWhatTheBuildDoesNotKnow(t *testing.T) {
	info := Info{Version: testVersion, GoVersion: testGoVersion, Platform: testPlatform}
	keys := keysOf(t, info.KeysAndValues())
	if len(keys) != 3 {
		t.Fatalf("expected only the populated fields, got %v", keys)
	}
	for _, absent := range []string{commitKey, dateKey, imageKey, chartKey, releaseKey} {
		if slices.Contains(keys, absent) {
			t.Fatalf("expected %q to be omitted, got %v", absent, keys)
		}
	}
}

// TestStringRendersOneFieldPerLine verifies the --version output is readable and carries the same fields.
func TestStringRendersOneFieldPerLine(t *testing.T) {
	info := Info{Version: testVersion, GoVersion: testGoVersion, Image: testImage}
	lines := strings.Split(info.String(), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected one line per populated field, got %v", lines)
	}
	if lines[0] != versionKey+": "+testVersion || lines[2] != imageKey+": "+testImage {
		t.Fatalf("expected each line to name its field, got %v", lines)
	}
}

// TestShortCommitLeavesOtherFormsAlone verifies an already short or non-hash value is not truncated.
func TestShortCommitLeavesOtherFormsAlone(t *testing.T) {
	for value, expected := range map[string]string{
		"":                    "",
		"1081fb2":             "1081fb2",
		testShortCommit:       testShortCommit,
		testCommit:            testShortCommit,
		testCommit + "-dirty": testShortCommit + "-dirty",
		"unknown":             "unknown",
	} {
		if shortened := shortCommit(value); shortened != expected {
			t.Fatalf("expected %q for %q, got %q", expected, value, shortened)
		}
	}
}

// TestGetReportsTheRunningBinary verifies the exported entry point resolves without panicking.
func TestGetReportsTheRunningBinary(t *testing.T) {
	if info := Get(); info.Version == "" || info.GoVersion == "" || info.Platform == "" {
		t.Fatalf("expected the running binary to describe itself, got %+v", info)
	}
}
