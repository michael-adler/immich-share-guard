# immich-share-guard is a single static binary with no dependencies, so the
# image holds nothing else. The builder runs on the build host's architecture
# and cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags=-s -o /immich-share-guard ./cmd/immich-share-guard

# distroless/static has no shell or package manager, only CA certificates,
# time zone data and a nonroot user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /immich-share-guard /immich-share-guard
USER nonroot
ENTRYPOINT ["/immich-share-guard"]
