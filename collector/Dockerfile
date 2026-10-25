# AgentWard collector image.
# Build from the repo root:  docker build -f collector/Dockerfile -t agentward-collector .

# Stage 1: build the collector binary with the OpenTelemetry builder (ocb).
FROM golang:1.26 AS build

RUN go install go.opentelemetry.io/collector/cmd/builder@v0.160.0

WORKDIR /src/collector
# Download the processor's Go modules first so they stay cached when only
# the source changes.
COPY collector/processor/taintpolicy/go.mod collector/processor/taintpolicy/go.sum ./processor/taintpolicy/
RUN cd processor/taintpolicy && go mod download
COPY collector/processor ./processor
COPY collector/builder.yaml ./builder.yaml

# builder.yaml points the replace at an absolute path on a dev machine.
# Point it at the source copied into this image instead.
RUN sed -i 's#=> .*/collector/processor/taintpolicy#=> /src/collector/processor/taintpolicy#' builder.yaml \
 && grep -q '=> /src/collector/processor/taintpolicy' builder.yaml

ENV CGO_ENABLED=0
# ocb already strips the binary (-s -w). The load_balancing exporter adds
# about 35 MB (Kubernetes and AWS resolver clients); the image is about 85 MB.
RUN builder --config=builder.yaml \
 && mkdir -p /out/var/lib/agentward

# Stage 2: small runtime image with only the static binary, config and policy.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /src/collector/build/agentward-collector /agentward-collector
COPY collector/config.docker.yaml /etc/agentward/config.yaml
COPY collector/policy/pii_egress.rego /etc/agentward/policy/pii_egress.rego
# Writable by the nonroot user, for the optional file exporter.
COPY --from=build --chown=65532:65532 /out/var/lib/agentward /var/lib/agentward

# Any OTLP gRPC backend, as host:port.
ENV OTLP_EXPORT_ENDPOINT=jaeger:4317
# 4319 OTLP/HTTP, 4317 OTLP/gRPC, 13133 health check.
EXPOSE 4319 4317 13133
ENTRYPOINT ["/agentward-collector"]
CMD ["--config=/etc/agentward/config.yaml"]
