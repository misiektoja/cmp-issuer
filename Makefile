# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# YEAR defines the year value used for substituting the YEAR placeholder in the boilerplate header.
YEAR ?= $(shell date +%Y)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths=./api/... paths=./internal/... paths=./cmd/... output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths=./api/...

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

# GO_PACKAGES selects the packages the routine targets act on. test/e2e carries a build tag and runs
# from its own targets.
GO_PACKAGES = go list ./... | grep -v '/e2e'

# COVER_PACKAGES is the code the coverage figure is measured over. Coverage defaults to the package a
# test binary lives in, so without this a package carrying no test file of its own reports 0% even when
# every test run executes it. cmd is manager wiring and test/utils is scaffolding, so neither is counted.
COVER_PACKAGES ?= ./api/...,./internal/...

.PHONY: vet
vet: ## Run go vet against code.
	go vet $$($(GO_PACKAGES))

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$($(GO_PACKAGES)) -coverpkg=$(COVER_PACKAGES) -coverprofile cover.out

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# kubectl kuberc is disabled by default for test isolation; enable with:
# - KUBECTL_KUBERC=true
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
# CertManager version, empty for the suite default; pin one for a compatibility run with:
# - CERT_MANAGER_VERSION=v1.19.6
KIND_CLUSTER ?= cmp-issuer-test-e2e
# Kubernetes version for the Kind cluster, empty for the Kind default. Pin one with a published node
# image digest, for example KIND_NODE_IMAGE=kindest/node:v1.34.0, to run against another release.
KIND_NODE_IMAGE ?=
# The budget covers building the manager image and installing cert-manager before the specs run.
E2E_TIMEOUT ?= 20m

.PHONY: setup-test-e2e
setup-test-e2e: kind ## Set up a Kind cluster for e2e tests if it does not exist
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'$(if $(KIND_NODE_IMAGE), on $(KIND_NODE_IMAGE),)..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) $(if $(KIND_NODE_IMAGE),--image $(KIND_NODE_IMAGE),) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) go test -tags=e2e ./test/e2e/ -v -ginkgo.v \
		-ginkgo.label-filter='!ejbca' -timeout $(E2E_TIMEOUT)
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

# The e2e suite can enroll from a real CMP server instead of only proving the controller contract. The
# server is EJBCA Community Edition in an image that already carries its certification authority, its
# CMP aliases and a TLS certificate issued for the Service name below, so a run costs a container start
# rather than a full server setup. See test/e2e/ejbca/README.md.
## EJBCA_VERSION is the upstream release the CMP server image is built from.
EJBCA_VERSION ?= 9.3.7
## EJBCA_IMAGE_REVISION advances when the baked configuration changes without an upstream release.
EJBCA_IMAGE_REVISION ?= 1
## EJBCA_TEST_IMAGE is the preconfigured CMP server image that the enrollment specs start.
EJBCA_TEST_IMAGE ?= ghcr.io/misiektoja/cmp-issuer-ejbca-test:$(EJBCA_VERSION)-$(EJBCA_IMAGE_REVISION)
## EJBCA_HOSTNAME is baked into the TLS server certificate and has to stay the Service name that
## test/e2e/ejbca_test.go reaches the server through, otherwise the HTTPS specs cannot verify it.
EJBCA_HOSTNAME ?= ejbca.cmp-issuer-e2e-ejbca.svc.cluster.local
## The budget covers building the manager image, installing cert-manager and starting the CMP server.
E2E_EJBCA_TIMEOUT ?= 30m

.PHONY: ejbca-test-image
ejbca-test-image: ## Build the preconfigured CMP server image that the enrollment e2e tests use.
	EJBCA_VERSION=$(EJBCA_VERSION) EJBCA_TEST_IMAGE=$(EJBCA_TEST_IMAGE) EJBCA_HOSTNAME=$(EJBCA_HOSTNAME) \
		CONTAINER_TOOL=$(CONTAINER_TOOL) test/e2e/ejbca/build-image.sh

.PHONY: ejbca-test-image-settings
ejbca-test-image-settings: ## Print the CMP server image settings as key=value pairs.
	@echo "image=$(EJBCA_TEST_IMAGE)"
	@echo "version=$(EJBCA_VERSION)"
	@echo "hostname=$(EJBCA_HOSTNAME)"

.PHONY: ejbca-test-image-present
ejbca-test-image-present: ## Make the CMP server image available locally, pulling it or building it.
	@$(CONTAINER_TOOL) image inspect $(EJBCA_TEST_IMAGE) >/dev/null 2>&1 \
		|| $(CONTAINER_TOOL) pull $(EJBCA_TEST_IMAGE) \
		|| $(MAKE) ejbca-test-image

.PHONY: test-e2e-ejbca
test-e2e-ejbca: setup-test-e2e ejbca-test-image-present manifests generate fmt vet ## Run the e2e enrollment tests against a CMP server in the cluster.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) EJBCA_TEST_IMAGE=$(EJBCA_TEST_IMAGE) \
		go test -tags=e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter='ejbca' -timeout $(E2E_EJBCA_TIMEOUT)
	$(MAKE) cleanup-test-e2e

# The workflows are linted here rather than in their own target so that one command covers everything
# a change can break, and so a mistyped trigger, an undefined secret or a bad expression is reported
# before a push rather than by a workflow run that has already started.
.PHONY: lint
lint: golangci-lint actionlint ## Run the Go and GitHub Actions linters.
	"$(GOLANGCI_LINT)" run
	"$(ACTIONLINT)"

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Documentation

# PYTHON selects the interpreter that provides the MkDocs toolchain.
PYTHON ?= python3

.PHONY: docs-deps
docs-deps: ## Install the pinned documentation build dependencies.
	$(PYTHON) -m pip install -r docs/requirements.txt

.PHONY: docs-build
docs-build: ## Build the documentation site and fail on any warning.
	$(PYTHON) -m mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Serve the documentation site locally with live reload.
	$(PYTHON) -m mkdocs serve

# Release artifact names
#
# VERSION labels every release artifact written under dist, for example VERSION=v0.1.0. The targets
# that write one require it, so an artifact names the release it carries, a second build cannot
# overwrite the first, and a file that has been copied out of dist still says where it came from.
# Set it to the tag carried by IMG, the two are not derived from each other.
VERSION ?=

.PHONY: require-version
require-version:
	@test -n "$(VERSION)" || { echo "Set VERSION, for example VERSION=v0.1.0" >&2; exit 1; }

# Build identity
#
# The manager reports these in its startup log line and from its --version flag, so a support log
# says which release, which commit and which image reference produced the running binary. A release
# sets VERSION and every other build falls back to the commit description, so a development image
# still names the tree it came from. GIT_DESCRIBE, GIT_COMMIT and BUILD_DATE fall back again for a
# build from a source archive, where there is no repository to ask.
GIT_DESCRIBE = $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
## GIT_DIRTY marks a build from a modified tree, using the same definition git describe --dirty uses,
## so a stamped commit cannot claim to be a build of that commit as it was committed.
GIT_DIRTY = $(shell git diff-index --quiet HEAD -- 2>/dev/null || echo -dirty)
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)$(GIT_DIRTY)
## BUILD_DATE is the commit date rather than the wall clock, so rebuilding the same commit produces
## the same binary. A tree with no repository falls back to the time of the build.
BUILD_DATE ?= $(shell TZ=UTC0 git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_VERSION = $(if $(VERSION),$(VERSION),$(GIT_DESCRIBE))

## VERSION_PACKAGE holds the variables the linker stamps. Renaming the package or any of the four
## variables breaks the stamp silently, because the linker ignores an -X flag it cannot resolve.
VERSION_PACKAGE = github.com/misiektoja/cmp-issuer/internal/version
LDFLAGS = -X $(VERSION_PACKAGE).version=$(BUILD_VERSION) -X $(VERSION_PACKAGE).gitCommit=$(GIT_COMMIT) -X $(VERSION_PACKAGE).buildDate=$(BUILD_DATE)
## IMAGE_BUILD_ARGS forwards the same identity to the Dockerfile, which applies it with the same
## flags. IMG is stamped as well, so the binary names the image reference it was published under.
IMAGE_BUILD_ARGS = --build-arg VERSION=$(BUILD_VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg IMAGE=$(IMG)

## CHART_VERSION is VERSION without the leading v, because a Helm chart version has to be bare SemVer.
## The packaged chart is therefore the one artifact whose name does not carry the tag verbatim.
CHART_VERSION = $(VERSION:v%=%)

## Multi-architecture image archive that the air-gapped bundle carries
IMAGE_ARCHIVE ?= dist/cmp-issuer-$(VERSION)-image.tar
## Platform list of that archive, written by the build and read back when the bundle is assembled
IMAGE_PLATFORMS ?= dist/cmp-issuer-$(VERSION)-image-platforms.txt
## Self-contained install manifest built from config/default
INSTALLER_MANIFEST ?= dist/cmp-issuer-$(VERSION)-install.yaml
## Packaged Helm chart, written by helm package rather than by a target here
CHART_ARCHIVE ?= dist/cmp-issuer-$(CHART_VERSION).tgz
## Air-gapped bundle, and the directory it unpacks to, which carries the same name as the archive
BUNDLE_DIR = cmp-issuer-$(VERSION)-airgap
BUNDLE_ARCHIVE = dist/$(BUNDLE_DIR).tar.gz

## SBOM_VERSION names the bill of materials. The routine supply chain run publishes one for a commit
## rather than for a release, so it falls back to the commit description instead of to a name that
## could belong to any build.
SBOM_VERSION = $(BUILD_VERSION)
SBOM_FILE ?= dist/cmp-issuer-$(SBOM_VERSION)-sbom.cdx.json

## Flags that keep the bundle free of platform metadata. bsdtar on macOS copies extended attributes
## such as com.apple.provenance into pax headers, which makes GNU tar on Linux warn once per entry
## while extracting. Each flag is probed because GNU tar accepts only the first one.
TAR_PORTABLE_FLAGS := $(shell for flag in --no-xattrs --no-mac-metadata --no-acls --no-fflags; do tar $$flag --version >/dev/null 2>&1 && printf '%s ' $$flag; done)

##@ Supply chain

.PHONY: govulncheck
govulncheck: govulncheck-tool ## Report known vulnerabilities that reach the module or its dependencies.
	"$(GOVULNCHECK)" $$($(GO_PACKAGES))

# GITLEAKS_LOG_OPTS selects the history the commit scan walks. gh-pages carries the rendered
# documentation site rather than source, and its HTML trips the private-key rule on the placeholder key
# block in docs/guide/message-protection.md once mkdocs wraps that block in markup. The markdown the
# branch is generated from is scanned in full, so excluding the branch loses no coverage. An exclude
# pattern that matches no ref is ignored, so this stays correct where gh-pages was never fetched.
GITLEAKS_LOG_OPTS ?= --full-history --exclude=refs/remotes/*/gh-pages --exclude=refs/heads/gh-pages --all

.PHONY: gitleaks
gitleaks: gitleaks-tool ## Scan the working tree and the commit history for leaked credentials.
# The gitleaks config allowlists local/ so the working tree scan skips uncommitted lab material. That
# allowlist also applies to the history scan, so a tracked file under local/ would evade both. The
# directory is ignored by git, and this guard fails the target if anything there is tracked anyway.
	@test -z "$$(git ls-files local/ 2>/dev/null)" || { echo "error: tracked files under local/ are excluded from the gitleaks scan by .gitleaks.toml"; exit 1; }
	"$(GITLEAKS)" dir . --config .gitleaks.toml --redact --no-banner
	"$(GITLEAKS)" git . --config .gitleaks.toml --redact --no-banner --log-opts="$(GITLEAKS_LOG_OPTS)"

# Standard library security fixes ship in Go patch releases, so a module left on an older patch reports
# them through govulncheck even when its dependency graph has not moved. These targets are kept out of
# the supply-chain target on purpose: govulncheck already fails on the consequence, and reaching go.dev
# would make an offline run of that target fail for a reason unrelated to any vulnerability.
.PHONY: go-patch-check
go-patch-check: ## Report whether go.mod declares the newest Go patch in its release series.
	hack/go-patch-version.sh check

.PHONY: go-patch-update
go-patch-update: ## Move go.mod and the documented prerequisite to the newest Go patch in its series.
	hack/go-patch-version.sh update

.PHONY: sbom
sbom: cyclonedx-gomod ## Generate a CycloneDX software bill of materials for the module. Specify VERSION for a release.
	mkdir -p dist
	"$(CYCLONEDX_GOMOD)" mod -licenses -json -output "$(SBOM_FILE)" .
	@echo "Wrote $(SBOM_FILE)"

# TRIVY_IMAGE runs the scanner as a container so no scanner binary has to be installed.
TRIVY_IMAGE ?= aquasec/trivy:0.74.0
TRIVY_CACHE ?= $(HOME)/.cache/trivy
TRIVY_SEVERITY ?= HIGH,CRITICAL

# The image is scanned from an exported archive so no container runtime socket has to be shared. The
# archive is scanner input rather than a release artifact, so it is written to its own directory and
# never sits next to the versioned archives the release ships.
.PHONY: scan-image
scan-image: ## Scan the manager image for known operating system and language vulnerabilities.
	mkdir -p dist/scan "$(TRIVY_CACHE)"
	$(CONTAINER_TOOL) save "${IMG}" -o dist/scan/manager-image.tar
	$(CONTAINER_TOOL) run --rm \
		-v "$(TRIVY_CACHE)":/root/.cache/trivy \
		-v "$(CURDIR)/dist/scan":/scan \
		$(TRIVY_IMAGE) image --scanners vuln --severity $(TRIVY_SEVERITY) \
		--ignore-unfixed --exit-code 1 --input /scan/manager-image.tar

.PHONY: supply-chain
supply-chain: govulncheck gitleaks sbom ## Run every supply chain check that needs no container image.

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -ldflags "$(LDFLAGS)" -o bin/manager cmd/main.go

# The downloaded tools under bin are deliberately kept, so a clean build does not re-download the
# whole toolchain. Remove those with clean-tools. Removing bin/manager does change the mtime of bin
# itself, which every tool target depends on, so the next lint run rebuilds the custom golangci-lint
# binary once. The tools themselves are not downloaded again.
.PHONY: clean
clean: ## Remove build, test and documentation outputs, keeping the downloaded tools.
	rm -f bin/manager cover.out Dockerfile.cross
	rm -rf dist site

# setup-envtest extracts the Kubernetes test assets into a read-only directory, so the write bit has
# to be restored before anything inside it can be unlinked.
.PHONY: clean-tools
clean-tools: ## Remove the tool binaries downloaded into bin.
	@test ! -d "$(LOCALBIN)" || chmod -R u+w "$(LOCALBIN)"
	rm -rf "$(LOCALBIN)"

.PHONY: clean-all
clean-all: clean clean-tools ## Remove every generated artifact, including the downloaded tools.

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build $(IMAGE_BUILD_ARGS) -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name cmp-issuer-builder
	$(CONTAINER_TOOL) buildx use cmp-issuer-builder
	- $(CONTAINER_TOOL) buildx build $(IMAGE_BUILD_ARGS) --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm cmp-issuer-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: require-version manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment. Specify IMG and VERSION.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > "$(INSTALLER_MANIFEST)"
	@echo "Wrote $(INSTALLER_MANIFEST)"

.PHONY: docker-archive
docker-archive: require-version ## Export the manager image for every release platform as an OCI archive. Specify IMG and VERSION.
	mkdir -p dist
	# The cross Dockerfile builds the Go binary on the native platform and cross-compiles for the
	# target, which is much faster than emulating the compiler. It lives under dist so no generated
	# file lands next to the source.
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > dist/Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name cmp-issuer-archiver
	$(CONTAINER_TOOL) buildx use cmp-issuer-archiver
	$(CONTAINER_TOOL) buildx build $(IMAGE_BUILD_ARGS) --platform=$(PLATFORMS) --tag ${IMG} --output type=oci,dest=$(IMAGE_ARCHIVE) -f dist/Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm cmp-issuer-archiver
	# Recorded here so the bundle describes the archive it actually carries rather than the current
	# value of PLATFORMS.
	echo "$(PLATFORMS)" > "$(IMAGE_PLATFORMS)"

.PHONY: docker-release
docker-release: require-version ## Push the manager image and export the same build as an OCI archive in one pass. Specify IMG and VERSION.
	mkdir -p dist
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > dist/Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name cmp-issuer-releaser
	$(CONTAINER_TOOL) buildx use cmp-issuer-releaser
	# Two exporters on one build, so the archive in the air-gapped bundle is bit for bit the image
	# that was published rather than a second build of the same source.
	$(CONTAINER_TOOL) buildx build $(IMAGE_BUILD_ARGS) --platform=$(PLATFORMS) --tag ${IMG} --output type=image,push=true --output type=oci,dest=$(IMAGE_ARCHIVE) -f dist/Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm cmp-issuer-releaser
	echo "$(PLATFORMS)" > "$(IMAGE_PLATFORMS)"

.PHONY: release-bundle
release-bundle: require-version ## Assemble the air-gapped install bundle from the artifacts already in dist. Specify VERSION.
	@test -f "$(IMAGE_ARCHIVE)" || { echo "Run docker-archive first, $(IMAGE_ARCHIVE) is missing" >&2; exit 1; }
	@test -f "$(IMAGE_PLATFORMS)" || { echo "Run docker-archive first, $(IMAGE_PLATFORMS) is missing" >&2; exit 1; }
	@test -f "$(INSTALLER_MANIFEST)" || { echo "Run build-installer first, $(INSTALLER_MANIFEST) is missing" >&2; exit 1; }
	@test -f "$(CHART_ARCHIVE)" || { echo "Package the chart first, $(CHART_ARCHIVE) is missing" >&2; exit 1; }
	@test -f "$(SBOM_FILE)" || { echo "Run sbom with the same VERSION first, $(SBOM_FILE) is missing" >&2; exit 1; }
	# Every input is named after $(VERSION), so a rebuild replaces the staged copy of each one. The
	# directory is still cleared first, because an earlier release staged here would otherwise leave
	# its own image archive and chart behind and ship two versions of both.
	rm -rf "dist/$(BUNDLE_DIR)"
	mkdir -p "dist/$(BUNDLE_DIR)/images" "dist/$(BUNDLE_DIR)/charts"
	cp "$(IMAGE_ARCHIVE)" "dist/$(BUNDLE_DIR)/images/"
	cp "$(CHART_ARCHIVE)" "dist/$(BUNDLE_DIR)/charts/"
	cp "$(INSTALLER_MANIFEST)" "$(SBOM_FILE)" README.md RELEASE_NOTES.md LICENSE THIRD_PARTY_NOTICES.md "dist/$(BUNDLE_DIR)/"
	# The contents block is aligned by a second printf, which reuses its format for each name and
	# description pair, so the file names stay readable however long they are.
	{ \
		printf '%s\n' \
			"cmp-issuer $(VERSION) air-gapped bundle" \
			"" \
			"Every file here carries $(VERSION), so one copied out of the bundle still names the release it came from." \
			"" \
			"Contents:"; \
		printf '  %-36s %s\n' \
			"images/$(notdir $(IMAGE_ARCHIVE))" "OCI archive of the manager image, $$(cat $(IMAGE_PLATFORMS))" \
			"charts/$(notdir $(CHART_ARCHIVE))" "packaged Helm chart" \
			"$(notdir $(INSTALLER_MANIFEST))" "self-contained manifest install" \
			"$(notdir $(SBOM_FILE))" "CycloneDX bill of materials"; \
		printf '%s\n' \
			"" \
			"1. Load the image into your own registry:" \
			"     skopeo copy --all oci-archive:images/$(notdir $(IMAGE_ARCHIVE)) docker://<registry>/cmp-issuer:$(VERSION)" \
			"   or import it straight into a node runtime:" \
			"     ctr --namespace k8s.io images import images/$(notdir $(IMAGE_ARCHIVE))" \
			"" \
			"2. Install, pointing the chart at that registry:" \
			"     helm install cmp-issuer charts/$(notdir $(CHART_ARCHIVE)) --namespace cmp-issuer-system --create-namespace --set manager.image.repository=<registry>/cmp-issuer" \
			"" \
			"   or apply the manifest instead, after editing the manager image it names:" \
			"     kubectl apply -f $(notdir $(INSTALLER_MANIFEST))" \
			"" \
			"Documentation: https://misiektoja.github.io/cmp-issuer/"; \
	} > "dist/$(BUNDLE_DIR)/INSTALL.txt"
	tar $(TAR_PORTABLE_FLAGS) -czf "$(BUNDLE_ARCHIVE)" -C dist "$(BUNDLE_DIR)"
	@echo "Wrote $(BUNDLE_ARCHIVE)"

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= $(LOCALBIN)/kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
GOVULNCHECK ?= $(LOCALBIN)/govulncheck
GITLEAKS ?= $(LOCALBIN)/gitleaks
ACTIONLINT ?= $(LOCALBIN)/actionlint
CYCLONEDX_GOMOD ?= $(LOCALBIN)/cyclonedx-gomod
HELM ?= $(LOCALBIN)/helm

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.21.0
KIND_VERSION ?= v0.32.0
GOVULNCHECK_VERSION ?= v1.7.0
GITLEAKS_VERSION ?= v8.30.1
ACTIONLINT_VERSION ?= v1.7.12
CYCLONEDX_GOMOD_VERSION ?= v1.11.0
HELM_VERSION ?= v3.20.1

#ENVTEST_VERSION is the controller-runtime version to use for setup-envtest, derived from go.mod
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v")

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.12.2
# The plugin build below replaces the binary go-install-tool installed, which destroys the symlink it
# uses to recognise an existing install, so its own skip check cannot be relied on here. This sentinel
# is what decides instead. It is written last, so a later change inside bin cannot make the target look
# stale, and a version bump renames it and forces a fresh build.
GOLANGCI_LINT_STAMP = $(LOCALBIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION).stamp
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: kind
kind: $(KIND) ## Download kind locally if necessary.
$(KIND): $(LOCALBIN)
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))

.PHONY: govulncheck-tool
govulncheck-tool: $(GOVULNCHECK) ## Download govulncheck locally if necessary.
$(GOVULNCHECK): $(LOCALBIN)
	$(call go-install-tool,$(GOVULNCHECK),golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

.PHONY: gitleaks-tool
gitleaks-tool: $(GITLEAKS) ## Download gitleaks locally if necessary.
$(GITLEAKS): $(LOCALBIN)
	$(call go-install-tool,$(GITLEAKS),github.com/zricethezav/gitleaks/v8,$(GITLEAKS_VERSION))

.PHONY: actionlint
actionlint: $(ACTIONLINT) ## Download actionlint locally if necessary.
$(ACTIONLINT): $(LOCALBIN)
	$(call go-install-tool,$(ACTIONLINT),github.com/rhysd/actionlint/cmd/actionlint,$(ACTIONLINT_VERSION))

.PHONY: cyclonedx-gomod
cyclonedx-gomod: $(CYCLONEDX_GOMOD) ## Download cyclonedx-gomod locally if necessary.
$(CYCLONEDX_GOMOD): $(LOCALBIN)
	$(call go-install-tool,$(CYCLONEDX_GOMOD),github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod,$(CYCLONEDX_GOMOD_VERSION))

.PHONY: helm
helm: $(HELM) ## Download helm locally if necessary.
$(HELM): $(LOCALBIN)
	$(call go-install-tool,$(HELM),helm.sh/helm/v3/cmd/helm,$(HELM_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT_STAMP) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT_STAMP): | $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@if test -f .custom-gcl.yml; then \
		echo "Building custom golangci-lint with plugins..."; \
		"$(GOLANGCI_LINT)" custom --destination "$(LOCALBIN)" --name golangci-lint-custom; \
		mv -f "$(LOCALBIN)/golangci-lint-custom" "$(GOLANGCI_LINT)"; \
	fi
	@touch "$@"

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

##@ Helm Deployment

## The Helm binary is pinned and installed by the helm target in the Dependencies section
## Namespace to deploy the Helm release
HELM_NAMESPACE ?= cmp-issuer-system
## Name of the Helm release
HELM_RELEASE ?= cmp-issuer
## Path to the Helm chart directory
HELM_CHART_DIR ?= charts/cmp-issuer
## Additional arguments to pass to helm commands
HELM_EXTRA_ARGS ?=
## Kubernetes version the lint render targets. Without a reachable cluster helm assumes v1.20.0, which
## the chart's kubeVersion range rejects, so the render is pinned to a version the project verifies
HELM_KUBE_VERSION ?= v1.34.0

.PHONY: helm-lint
helm-lint: helm ## Validate that the chart renders and passes the Helm linter.
	@test ! -d charts/chart || { echo "charts/chart exists, so a kubebuilder Helm plugin run scaffolded a second chart beside $(HELM_CHART_DIR). Move any regenerated templates into $(HELM_CHART_DIR) and delete charts/chart." >&2; exit 1; }
	$(HELM) lint $(HELM_CHART_DIR) --kube-version $(HELM_KUBE_VERSION)
	$(HELM) template $(HELM_RELEASE) $(HELM_CHART_DIR) --namespace $(HELM_NAMESPACE) --kube-version $(HELM_KUBE_VERSION) > /dev/null

.PHONY: helm-deploy
helm-deploy: helm ## Deploy manager to the K8s cluster via Helm. Specify an image with IMG.
	$(HELM) upgrade --install $(HELM_RELEASE) $(HELM_CHART_DIR) \
		--namespace $(HELM_NAMESPACE) \
		--create-namespace \
		--set manager.image.repository=$${IMG%:*} \
		--set manager.image.tag=$${IMG##*:} \
		--wait \
		--timeout 5m \
		$(HELM_EXTRA_ARGS)

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall the Helm release from the K8s cluster.
	$(HELM) uninstall $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)

.PHONY: helm-status
helm-status: ## Show Helm release status.
	$(HELM) status $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)

.PHONY: helm-history
helm-history: ## Show Helm release history.
	$(HELM) history $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)

.PHONY: helm-rollback
helm-rollback: ## Rollback to previous Helm release.
	$(HELM) rollback $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)
