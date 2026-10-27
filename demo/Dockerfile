# Taintward demo image: runs the HR bot breach simulator once.
# Build from the repo root:  docker build -f demo/Dockerfile -t taintward-demo .
# The base image is pinned by digest (same as deploy/gateway.Dockerfile).
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Runtime deps plus the small spaCy model that taintward/sdk/detect.py pins
# (not the 400MB en_core_web_lg), from the hashed lock file made by
# deploy/requirements/update.sh. Same layer as deploy/gateway.Dockerfile.
COPY deploy/requirements/runtime.txt /tmp/req/runtime.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: --retries 10 --timeout 60 \
        -r /tmp/req/runtime.txt \
 && rm -rf /root/.cache

COPY taintward ./taintward
COPY demo ./demo

ENV COLLECTOR_ENDPOINT=http://taintward-collector:4319/v1/traces

# Wait until the collector port is open, then run the breach simulator.
CMD ["python", "demo/run_in_docker.py"]
