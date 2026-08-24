# Build the manager binary
FROM golang:1.27 AS builder
ARG TARGETOS
ARG TARGETARCH

# Build identity stamped into the binary, so the manager can name in its own startup log the release,
# the commit and the image reference it came from. The Makefile passes all four, and the defaults keep
# a plain docker build working. .dockerignore excludes .git, so the version control metadata the Go
# toolchain would otherwise embed is not available here and these arguments are the only source.
ARG VERSION=development
ARG GIT_COMMIT=
ARG BUILD_DATE=
ARG IMAGE=
ARG VERSION_PACKAGE=github.com/misiektoja/cmp-issuer/internal/version

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -ldflags "-X ${VERSION_PACKAGE}.version=${VERSION} -X ${VERSION_PACKAGE}.gitCommit=${GIT_COMMIT} -X ${VERSION_PACKAGE}.buildDate=${BUILD_DATE} -X ${VERSION_PACKAGE}.image=${IMAGE}" -o manager ./cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
