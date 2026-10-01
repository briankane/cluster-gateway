# Build from the repository root: docker build -f plugins/aws/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.sum ./
COPY pkg/credentialprovider/ pkg/credentialprovider/
COPY plugins/aws/go.mod plugins/aws/go.sum plugins/aws/
RUN cd plugins/aws && go mod download
COPY plugins/aws/ plugins/aws/

RUN cd plugins/aws && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /aws-credential-plugin .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /aws-credential-plugin /aws-credential-plugin
USER 65532:65532
ENTRYPOINT ["/aws-credential-plugin"]
