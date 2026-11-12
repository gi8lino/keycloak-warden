# syntax=docker/dockerfile:1.29

# Build on the build machine while targeting the requested image platform.
FROM --platform=$BUILDPLATFORM golang:1.27.4 AS build

ENV CGO_ENABLED=0
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
  go mod download

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  GOOS=$TARGETOS GOARCH=$TARGETARCH \
  go build -trimpath \
  -ldflags="-s -w -X main.Version=${VERSION}" \
  -o /keycloak-warden ./cmd/warden

# Make the database and temporary directories writable by non-root and
# arbitrary OpenShift UIDs belonging to group 0.
RUN install -d -o 0 -g 0 -m 2775 /outfs/config /outfs/data /outfs/tmp

FROM gcr.io/distroless/static:nonroot

COPY --from=build /keycloak-warden /keycloak-warden
# Copy the directory entries themselves so their group-writable modes survive.
COPY --from=build /outfs/ /

ENV HOME=/tmp \
  WARDEN__LISTEN_ADDRESS=:8080 \
  WARDEN__MANAGEMENT_LISTEN_ADDRESS=:8081 \
  WARDEN__DATABASE=/data/warden.db

WORKDIR /data
USER 65532:0

ENTRYPOINT ["/keycloak-warden"]
CMD ["serve"]
