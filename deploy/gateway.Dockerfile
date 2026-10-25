# Taintward MCP gateway image.
# Build from the repo root:  docker build -f deploy/gateway.Dockerfile -t taintward-gateway .
#
# Default command serves MCP over HTTP on port 8811 with the config at
# /etc/taintward/gateway.yaml (mount your own there). For stdio, run
#   docker run -i --rm taintward-gateway python -m taintward.gateway --config /etc/taintward/gateway.yaml
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Same first layers as demo/Dockerfile, so a machine that built the demo
# reuses this layer from the build cache: runtime deps from pyproject.toml
# plus the small spaCy model that taintward/sdk/detect.py uses.
COPY pyproject.toml ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > /tmp/req.txt \
 && pip install -r /tmp/req.txt \
 && python -m spacy download en_core_web_sm \
 && rm -rf /root/.cache /tmp/req.txt

# The mcp extra (mcp, PyYAML, uvicorn) and the redis and postgres extras, so
# several replicas can share sessions (TAINTWARD_SESSION_STORE) and the
# token vault (TAINTWARD_VAULT).
RUN python -c "import tomllib; x=tomllib.load(open('pyproject.toml','rb'))['project']['optional-dependencies']; print('\n'.join(x['mcp'] + x['redis'] + x['postgres']))" > /tmp/req.txt \
 && pip install --retries 10 --timeout 60 -r /tmp/req.txt \
 && rm -rf /root/.cache /tmp/req.txt

# preshed 3.0.14 breaks loading the spaCy 3.8.16 model ("Python int too large
# to convert to C ssize_t"), and taintward/sdk/detect.py then finds nothing. Pin it.
RUN pip install --retries 10 --timeout 60 "preshed<3.0.14" && rm -rf /root/.cache

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
