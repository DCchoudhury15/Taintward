# Taintward MCP gateway image.
# Build from the repo root:  docker build -f deploy/gateway.Dockerfile -t taintward-gateway .
#
# Default command serves MCP over HTTP on port 8811 with the config at
# /etc/taintward/gateway.yaml (mount your own there). For stdio, run
#   docker run -i --rm taintward-gateway python -m taintward.gateway --config /etc/taintward/gateway.yaml
#
# The base image is pinned by digest. To update it:
#   skopeo inspect --raw docker://docker.io/library/python:3.12-slim | sha256sum
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

LABEL org.opencontainers.image.title="taintward-gateway" \
      org.opencontainers.image.description="Taintward MCP gateway: redacts and blocks PII and secrets in MCP tool calls" \
      org.opencontainers.image.source="https://gitlab.com/divyanshuchoudhury51/taintward" \
      org.opencontainers.image.url="https://taintward.vercel.app" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies come from hashed lock files (deploy/requirements/, made by
# deploy/requirements/update.sh from constraints.txt). pip checks every
# file against its sha256, and installs wheels only, so nothing is built
# from source during the image build.
#
# First layer: the runtime deps plus the small spaCy model that
# taintward/sdk/detect.py uses. Same as demo/Dockerfile, so a machine that
# built the demo reuses this layer from the build cache.
COPY deploy/requirements/runtime.txt /tmp/req/runtime.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: --retries 10 --timeout 60 \
        -r /tmp/req/runtime.txt \
 && rm -rf /root/.cache

# Second layer: the mcp extra (mcp, PyYAML, uvicorn) and the redis and
# postgres extras, so several replicas can share sessions
# (TAINTWARD_SESSION_STORE) and the token vault (TAINTWARD_VAULT).
COPY deploy/requirements/gateway.txt /tmp/req/gateway.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: --retries 10 --timeout 60 \
        -r /tmp/req/gateway.txt \
 && pip check \
 && rm -rf /root/.cache /tmp/req

COPY taintward ./taintward
# Fail the build if detection is broken. taintward/sdk/detect.py returns no findings
# (instead of an error) when Presidio or spaCy cannot load, which would let
# raw data through.
RUN TAINTWARD_ALLOW_DEMO_KEY=1 python -c "from taintward.sdk import detect; found = {d.entity_type for d in detect.detect_text('ssn 234-12-1234 key AKIAIOSFODNN7EXAMPLE')}; assert {'US_SSN', 'AWS_ACCESS_KEY'} <= found, found; print('detection ok', sorted(found))"
# Example config so the image starts on its own. The example upstream uses
# cwd "../..", which from /etc/taintward is not /app, so point it at /app.
RUN mkdir -p /etc/taintward \
 && sed 's#^    cwd: \.\./\.\.$#    cwd: /app#' taintward/gateway/example-config.yaml > /etc/taintward/gateway.yaml \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin taintward

USER 10001
EXPOSE 8811
CMD ["python", "-m", "taintward.gateway", "--config", "/etc/taintward/gateway.yaml", "--listen", "0.0.0.0:8811"]
