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

// Package version reports which build of the manager is running and which install deployed it.
package version

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/misiektoja/cmp-issuer/internal/logging"
)

// The linker stamps these at build time with -X, which is what the ldflags block in the Makefile
// passes and what the Dockerfile forwards from its build arguments. An unstamped build keeps the
// fallbacks below and fills what it can from the metadata the Go toolchain embeds, so a binary built
// with a plain go build still names the commit it came from.
var (
	version   = developmentVersion
	gitCommit = ""
	buildDate = ""
	image     = ""
)

const (
	// developmentVersion is what an unstamped build with no module version calls itself.
	developmentVersion = "development"
	// commitLength is how much of the commit hash is logged, which is enough to identify it uniquely.
	commitLength = 12
	// ImageEnvVar names the image reference the manager was deployed from.
	ImageEnvVar = "CMP_ISSUER_IMAGE"
	// ChartEnvVar names the Helm chart and version that installed the manager.
	ChartEnvVar = "CMP_ISSUER_CHART"
	// ReleaseEnvVar names the Helm release that installed the manager.
	ReleaseEnvVar = "CMP_ISSUER_RELEASE"
	// revisionSetting, revisionTimeSetting and modifiedSetting are the version control keys the Go
	// toolchain embeds in a binary built from a repository.
	revisionSetting     = "vcs.revision"
	revisionTimeSetting = "vcs.time"
	modifiedSetting     = "vcs.modified"
)

// The keys the identity renders. They are part of the log contract the troubleshooting page
// documents, so they are named here rather than repeated as literals.
const (
	versionKey   = "version"
	commitKey    = "gitCommit"
	dateKey      = "buildDate"
	goVersionKey = "goVersion"
	platformKey  = "platform"
	imageKey     = "image"
	chartKey     = "chart"
	releaseKey   = "release"
)

// Info describes the build the manager was compiled from and the install that deployed it.
type Info struct {
	Version   string
	GitCommit string
	BuildDate string
	GoVersion string
	Platform  string
	Image     string
	Chart     string
	Release   string
}

// Get returns the build and install identity of the running manager.
func Get() Info { return resolve(debug.ReadBuildInfo, os.LookupEnv) }

// resolve assembles the identity from the stamped values, the embedded build metadata and the environment.
func resolve(readBuildInfo func() (*debug.BuildInfo, bool), lookupEnv func(string) (string, bool)) Info {
	info := Info{
		Version:   version,
		GitCommit: shortCommit(gitCommit),
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Image:     image,
	}
	if build, ok := readBuildInfo(); ok && build != nil {
		applyBuildInfo(&info, build)
	}
	if info.Version == "" {
		info.Version = developmentVersion
	}
	// The install-time values are supplied by whoever deployed the manager rather than by the build,
	// so they are bounded like any other value the controller did not produce itself.
	for _, binding := range []struct {
		name   string
		target *string
	}{
		{ImageEnvVar, &info.Image},
		{ChartEnvVar, &info.Chart},
		{ReleaseEnvVar, &info.Release},
	} {
		if value, ok := lookupEnv(binding.name); ok && value != "" {
			*binding.target = logging.Text(value)
		}
	}
	return info
}

// applyBuildInfo fills in from the embedded module and version control metadata whatever the linker did not stamp.
func applyBuildInfo(info *Info, build *debug.BuildInfo) {
	if info.Version == "" || info.Version == developmentVersion {
		if moduleVersion := build.Main.Version; moduleVersion != "" && moduleVersion != "(devel)" {
			info.Version = moduleVersion
		}
	}
	var revision string
	var modified bool
	for _, setting := range build.Settings {
		switch setting.Key {
		case revisionSetting:
			revision = setting.Value
		case revisionTimeSetting:
			if info.BuildDate == "" {
				info.BuildDate = setting.Value
			}
		case modifiedSetting:
			modified = setting.Value == "true"
		}
	}
	if info.GitCommit == "" && revision != "" {
		info.GitCommit = shortCommit(revision)
		if modified {
			info.GitCommit += "-dirty"
		}
	}
}

// shortCommit trims a full commit hash to the logged length, leaving any other form untouched.
func shortCommit(commit string) string {
	name, suffix, _ := strings.Cut(commit, "-")
	if len(name) <= commitLength {
		return commit
	}
	name = name[:commitLength]
	if suffix == "" {
		return name
	}
	return name + "-" + suffix
}

// field is one rendered entry of the identity, in the order it is logged and printed.
type field struct {
	key   string
	value string
}

// fields returns the populated entries of the identity in log order, leaving out whatever this build does not know.
func (info Info) fields() []field {
	ordered := []field{
		{versionKey, info.Version},
		{commitKey, info.GitCommit},
		{dateKey, info.BuildDate},
		{goVersionKey, info.GoVersion},
		{platformKey, info.Platform},
		{imageKey, info.Image},
		{chartKey, info.Chart},
		{releaseKey, info.Release},
	}
	populated := make([]field, 0, len(ordered))
	for _, entry := range ordered {
		if entry.value == "" {
			continue
		}
		populated = append(populated, entry)
	}
	return populated
}

// KeysAndValues renders the identity as structured log fields.
func (info Info) KeysAndValues() []any {
	fields := info.fields()
	pairs := make([]any, 0, 2*len(fields))
	for _, entry := range fields {
		pairs = append(pairs, entry.key, entry.value)
	}
	return pairs
}

// String renders the identity as one line per field, which is what the --version flag prints.
func (info Info) String() string {
	fields := info.fields()
	lines := make([]string, 0, len(fields))
	for _, entry := range fields {
		lines = append(lines, entry.key+": "+entry.value)
	}
	return strings.Join(lines, "\n")
}
