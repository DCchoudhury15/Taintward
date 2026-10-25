# AgentWard MCP gateway image.
# Build from the repo root:  docker build -f gateway/Dockerfile -t agentward-gateway .
#
# Default command serves MCP over HTTP on port 8811 with the config at
# /etc/agentward/gateway.yaml (mount your own there). For stdio, run
#   docker run -i --rm agentward-gateway python -m gateway --config /etc/agentward/gateway.yaml
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Same first layers as demo/Dockerfile, so a machine that built the demo
# reuses this layer from the build cache: runtime deps from pyproject.toml
# plus the small spaCy model that sdk/detect.py uses.
COPY pyproject.toml ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > /tmp/req.txt \
 && pip install -r /tmp/req.txt \
 && python -m spacy download en_core_web_sm \
 && rm -rf /root/.cache /tmp/req.txt

# The mcp extra (mcp, PyYAML).
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['optional-dependencies']['mcp']))" > /tmp/req.txt \
 && pip install --retries 10 --timeout 60 -r /tmp/req.txt \
 && rm -rf /root/.cache /tmp/req.txt

COPY core ./core
COPY sdk ./sdk
COPY gateway ./gateway
# Example config so the image starts on its own. The example upstream uses
# cwd "..", which from /etc/agentward is not /app, so point it at /app.
RUN mkdir -p /etc/agentward \
 && sed 's#^    cwd: \.\.$#    cwd: /app#' gateway/example-config.yaml > /etc/agentward/gateway.yaml \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agentward

USER 10001
EXPOSE 8811
CMD ["python", "-m", "gateway", "--config", "/etc/agentward/gateway.yaml", "--listen", "0.0.0.0:8811"]
