# Taintward demo image: runs the HR bot breach simulator once.
# Build from the repo root:  docker build -f demo/Dockerfile -t taintward-demo .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install the runtime deps listed in pyproject.toml, plus the small spaCy
# model that taintward/sdk/detect.py pins (not the 400MB en_core_web_lg).
COPY pyproject.toml ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > /tmp/req.txt \
 && pip install -r /tmp/req.txt \
 && python -m spacy download en_core_web_sm \
 && rm -rf /root/.cache /tmp/req.txt

COPY taintward ./taintward
COPY demo ./demo

ENV COLLECTOR_ENDPOINT=http://taintward-collector:4319/v1/traces

# Wait until the collector port is open, then run the breach simulator.
CMD ["python", "demo/run_in_docker.py"]
