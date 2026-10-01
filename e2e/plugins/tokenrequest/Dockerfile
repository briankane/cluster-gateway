# Build from the repository root: docker build -f e2e/plugins/tokenrequest/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY pkg/ pkg/
COPY e2e/plugins/ e2e/plugins/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /tokenrequest ./e2e/plugins/tokenrequest

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /tokenrequest /tokenrequest
ENTRYPOINT ["/tokenrequest"]
