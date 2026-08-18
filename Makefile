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

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

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
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) go test -tags=e2e ./test/e2e/ -v -ginkgo.v -timeout $(E2E_TIMEOUT)
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

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

##@ Supply chain

.PHONY: govulncheck
govulncheck: govulncheck-tool ## Report known vulnerabilities that reach the module or its dependencies.
	"$(GOVULNCHECK)" ./...

.PHONY: gitleaks
gitleaks: gitleaks-tool ## Scan the working tree and the commit history for leaked credentials.
	"$(GITLEAKS)" dir . --config .gitleaks.toml --redact --no-banner
	"$(GITLEAKS)" git . --config .gitleaks.toml --redact --no-banner

.PHONY: sbom
sbom: cyclonedx-gomod ## Generate a CycloneDX software bill of materials for the module.
	mkdir -p dist
	"$(CYCLONEDX_GOMOD)" mod -licenses -json -output dist/cmp-issuer.cdx.json .

# TRIVY_IMAGE runs the scanner as a container so no scanner binary has to be installed.
TRIVY_IMAGE ?= aquasec/trivy:0.74.0
TRIVY_CACHE ?= $(HOME)/.cache/trivy
TRIVY_SEVERITY ?= HIGH,CRITICAL

# The image is scanned from an exported archive so no container runtime socket has to be shared.
.PHONY: scan-image
scan-image: ## Scan the manager image for known operating system and language vulnerabilities.
	mkdir -p dist "$(TRIVY_CACHE)"
	$(CONTAINER_TOOL) save "${IMG}" -o dist/manager-image.tar
	$(CONTAINER_TOOL) run --rm \
		-v "$(TRIVY_CACHE)":/root/.cache/trivy \
		-v "$(CURDIR)/dist":/scan \
		$(TRIVY_IMAGE) image --scanners vuln --severity $(TRIVY_SEVERITY) \
		--ignore-unfixed --exit-code 1 --input /scan/manager-image.tar

.PHONY: supply-chain
supply-chain: govulncheck gitleaks sbom ## Run every supply chain check that needs no container image.

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

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
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm cmp-issuer-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

## Multi-architecture image archive that the air-gapped bundle carries
IMAGE_ARCHIVE ?= dist/cmp-issuer-image.tar

.PHONY: docker-archive
docker-archive: ## Export the manager image for every release platform as an OCI archive. Specify an image with IMG.
	mkdir -p dist
	# The cross Dockerfile builds the Go binary on the native platform and cross-compiles for the
	# target, which is much faster than emulating the compiler. It lives under dist so no generated
	# file lands next to the source.
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > dist/Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name cmp-issuer-archiver
	$(CONTAINER_TOOL) buildx use cmp-issuer-archiver
	$(CONTAINER_TOOL) buildx build --platform=$(PLATFORMS) --tag ${IMG} --output type=oci,dest=$(IMAGE_ARCHIVE) -f dist/Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm cmp-issuer-archiver
	# Recorded here so the bundle describes the archive it actually carries rather than the current
	# value of PLATFORMS.
	echo "$(PLATFORMS)" > dist/image-platforms.txt

.PHONY: docker-release
docker-release: ## Push the manager image and export the same build as an OCI archive in one pass. Specify an image with IMG.
	mkdir -p dist
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > dist/Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name cmp-issuer-releaser
	$(CONTAINER_TOOL) buildx use cmp-issuer-releaser
	# Two exporters on one build, so the archive in the air-gapped bundle is bit for bit the image
	# that was published rather than a second build of the same source.
	$(CONTAINER_TOOL) buildx build --platform=$(PLATFORMS) --tag ${IMG} --output type=image,push=true --output type=oci,dest=$(IMAGE_ARCHIVE) -f dist/Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm cmp-issuer-releaser
	echo "$(PLATFORMS)" > dist/image-platforms.txt

.PHONY: release-bundle
release-bundle: ## Assemble the air-gapped install bundle from the artifacts already in dist. Specify VERSION.
	@test -n "$(VERSION)" || { echo "Set VERSION, for example VERSION=v0.1.0" >&2; exit 1; }
	@test -f "$(IMAGE_ARCHIVE)" || { echo "Run docker-archive first, $(IMAGE_ARCHIVE) is missing" >&2; exit 1; }
	@test -f dist/install.yaml || { echo "Run build-installer first, dist/install.yaml is missing" >&2; exit 1; }
	mkdir -p "dist/cmp-issuer-$(VERSION)/images" "dist/cmp-issuer-$(VERSION)/charts"
	cp "$(IMAGE_ARCHIVE)" "dist/cmp-issuer-$(VERSION)/images/"
	cp dist/cmp-issuer-*.tgz "dist/cmp-issuer-$(VERSION)/charts/"
	cp dist/install.yaml README.md RELEASE_NOTES.md LICENSE THIRD_PARTY_NOTICES.md "dist/cmp-issuer-$(VERSION)/"
	printf '%s\n' \
		"cmp-issuer $(VERSION) air-gapped bundle" \
		"" \
		"Contents:" \
		"  images/        OCI archive of the manager image, $$(cat dist/image-platforms.txt)" \
		"  charts/        packaged Helm chart" \
		"  install.yaml   self-contained manifest install" \
		"" \
		"1. Load the image into your own registry:" \
		"     skopeo copy --all oci-archive:images/$(notdir $(IMAGE_ARCHIVE)) docker://<registry>/cmp-issuer:$(VERSION)" \
		"   or import it straight into a node runtime:" \
		"     ctr --namespace k8s.io images import images/$(notdir $(IMAGE_ARCHIVE))" \
		"" \
		"2. Install, pointing the chart at that registry:" \
		"     helm install cmp-issuer charts/cmp-issuer-*.tgz --namespace cmp-issuer-system --create-namespace --set manager.image.repository=<registry>/cmp-issuer" \
		"" \
		"Documentation: https://misiektoja.github.io/cmp-issuer/" \
		> "dist/cmp-issuer-$(VERSION)/INSTALL.txt"
	tar czf "dist/cmp-issuer-$(VERSION)-airgap.tar.gz" -C dist "cmp-issuer-$(VERSION)"
	@echo "Wrote dist/cmp-issuer-$(VERSION)-airgap.tar.gz"

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
CYCLONEDX_GOMOD ?= $(LOCALBIN)/cyclonedx-gomod
HELM ?= $(LOCALBIN)/helm

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.21.0
KIND_VERSION ?= v0.32.0
GOVULNCHECK_VERSION ?= v1.7.0
GITLEAKS_VERSION ?= v8.30.1
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
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

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
