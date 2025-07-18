# hadolint global ignore=DL3059
# Build stage
FROM docker.io/library/golang:alpine@sha256:ddf52008bce1be455fe2b22d780b6693259aaf97b16383b6372f4b22dd33ad66 AS builder

WORKDIR /workspace

# Copy go.mod and go.sum (if they exist)
COPY go.mod ./
RUN go mod download && apk add --no-cache ca-certificates=20241121-r2

# Copy the source code
COPY ohhai.go ./

# Build the application with static linking
RUN CGO_ENABLED=0 go build -ldflags="-extldflags=-static" -o /go/bin/ohhai

# Create minimal /etc/passwd wiht appuser
RUN echo "appuser:x:10001:10001:App User:/:/sbin/nologin" > /etc/minimal-passwd

# Final minimal image
FROM scratch

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the static binary
COPY --from=builder /go/bin/ohhai /go/bin/ohhai

# Create and set nonroot user
COPY --from=builder /etc/minimal-passwd /etc/passwd
USER appuser

# Expose the port used by the application
EXPOSE 8080

# Set the entrypoint to the binary
ENTRYPOINT [ "/go/bin/ohhai" ]