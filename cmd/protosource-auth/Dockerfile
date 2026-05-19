# protosource-auth Container Apps image.
#
# Build context is the repository root:
#   docker build -f cmd/protosource-auth/Dockerfile -t <acr>/protosource-auth:<tag> .
#
# Honors $PORT at runtime (Container Apps sets this to the configured
# target_port). Defaults to 8080 if unset. Configure the service via
# PROTOSOURCE_AUTH_* env vars — see app/config.go for the full list.

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/protosource-auth ./cmd/protosource-auth

# Distroless static gives us a minimal runtime with the timezone DB and
# CA certificates needed for Cosmos DB / Key Vault TLS, and nothing
# else. The :nonroot tag runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/protosource-auth /protosource-auth
EXPOSE 8080
ENTRYPOINT ["/protosource-auth"]
