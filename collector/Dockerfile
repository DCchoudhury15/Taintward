# Taintward collector image.
# Build from the repo root:  docker build -f collector/Dockerfile -t taintward-collector .

# Base images are pinned by digest (multi-arch index digest), so a rebuild
# uses the same bytes. To update, resolve the new digest, for example:
#   skopeo inspect --raw docker://docker.io/library/golang:1.26 | sha256sum

# Stage 1: build the collector binary with the OpenTelemetry builder (ocb).
FROM golang:1.26@sha256:672c944cfd07599b5f1bb179869270cdc94c6254e41db4d431259693cb286b82 AS build

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
 && mkdir -p /out/var/lib/taintward

# Stage 2: small runtime image with only the static binary, config and policy.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

LABEL org.opencontainers.image.title="taintward-collector" \
      org.opencontainers.image.description="OpenTelemetry collector with the Taintward taint_policy processor" \
      org.opencontainers.image.source="https://gitlab.com/divyanshuchoudhury51/taintward" \
      org.opencontainers.image.url="https://taintward.vercel.app" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /src/collector/build/taintward-collector /taintward-collector
COPY collector/config.docker.yaml /etc/taintward/config.yaml
COPY collector/policy/pii_egress.rego /etc/taintward/policy/pii_egress.rego
# Writable by the nonroot user, for the optional file exporter.
COPY --from=build --chown=65532:65532 /out/var/lib/taintward /var/lib/taintward

# Any OTLP gRPC backend, as host:port.
ENV OTLP_EXPORT_ENDPOINT=jaeger:4317
# 4319 OTLP/HTTP, 4317 OTLP/gRPC, 13133 health check.
EXPOSE 4319 4317 13133
ENTRYPOINT ["/taintward-collector"]
CMD ["--config=/etc/taintward/config.yaml"]
