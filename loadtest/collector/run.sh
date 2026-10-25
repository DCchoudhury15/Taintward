#!/usr/bin/env bash
# Collector throughput test: telemetrygen -> agentward-collector (pinned CPUs).
#
# Usage (from the repo root):
#   docker build -f collector/Dockerfile -t agentward-collector:local .
#   loadtest/collector/run.sh                       # all scenarios, 1 and 2 CPUs
#   CPUS="1" DURATION=20 loadtest/collector/run.sh  # quicker
#
# For each scenario it starts the collector with --cpus=N, lets telemetrygen
# send as fast as it can, and after a warmup reads the collector's own
# counters (otelcol_exporter_sent_spans, otelcol_receiver_refused_spans) twice,
# DURATION seconds apart, to get spans per second. Nothing is published on
# host ports (the counters are read from the container IP).
#
# Scenarios:
#   policy-violation  taint_policy on; every span is sensitive + external with an
#                     SSN and an AWS key in the result (worst case: Rego + redaction)
#   policy-clean      taint_policy on; spans are not sensitive (Rego only)
#   passthrough       taint_policy off; same spans as policy-violation (baseline)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
IMAGE="${IMAGE:-agentward-collector:local}"
TGEN="${TGEN:-ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:v0.159.0}"
CPUS="${CPUS:-1 2}"
DURATION="${DURATION:-30}"
WARMUP="${WARMUP:-5}"
WORKERS="${WORKERS:-4}"
# Each telemetrygen process has one OTLP exporter, so it has only one request
# in flight at a time. Several processes are needed to load more than one core.
SENDERS="${SENDERS:-4}"
SCENARIOS="${SCENARIOS:-policy-violation policy-clean passthrough}"
NET="agentward-loadtest"
COLL="agentward-loadtest-collector"
TG="agentward-loadtest-tgen"   # sender containers are $TG-1 .. $TG-$SENDERS
OUT="${OUT:-$REPO/loadtest/results/collector-raw.tsv}"

stop_senders() {
  for i in $(seq 1 "$SENDERS"); do docker rm -f "$TG-$i" >/dev/null 2>&1 || true; done
}

cleanup() {
  docker rm -f "$COLL" >/dev/null 2>&1 || true
  stop_senders
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null

coll_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$COLL"; }

metric() {  # metric <name>: sum of a counter from the collector's /metrics
  curl -s "http://$(coll_ip):8888/metrics" \
    | awk -v m="$1" '$1 ~ "^"m"(_total)?({|$)" {s += $NF} END {printf "%d\n", s}'
}

cpu_usec() {  # CPU time used by a container (cgroup v2, systemd cgroup driver)
  awk '/usage_usec/ {print $2}' "/sys/fs/cgroup/system.slice/docker-$1.scope/cpu.stat" 2>/dev/null || echo 0
}

set_attrs() {
  case "$1" in
    policy-clean)
      ATTRS=(
        --telemetry-attributes 'agentward.sensitive=false'
        --telemetry-attributes 'agentward.destination="internal"'
        --telemetry-attributes 'gen_ai.tool.name="query_db"'
        --telemetry-attributes 'gen_ai.tool.call.result="employee Alice Lee, manager Bob Perez"'
      ) ;;
    *)
      ATTRS=(
        --telemetry-attributes 'agentward.sensitive=true'
        --telemetry-attributes 'agentward.taint.classes="pii,secret"'
        --telemetry-attributes 'agentward.destination="external"'
        --telemetry-attributes 'agentward.jurisdiction="us"'
        --telemetry-attributes 'gen_ai.tool.name="call_external_api"'
        --telemetry-attributes 'gen_ai.tool.call.arguments="ssn=[PII] key=[SECRET]"'
        --telemetry-attributes 'gen_ai.tool.call.result="ssn 234-12-1234 key AKIAIOSFODNN7EXAMPLE sent to audit@example.com"'
      ) ;;
  esac
}

[ -f "$OUT" ] || printf "scenario\tcpus\tsenders\tspans_per_s\trefused\tcollector_cpu_pct\n" > "$OUT"

for cpus in $CPUS; do
  for sc in $SCENARIOS; do
    cfg="$HERE/config.policy.yaml"
    [ "$sc" = passthrough ] && cfg="$HERE/config.passthrough.yaml"
    docker rm -f "$COLL" >/dev/null 2>&1 || true
    stop_senders
    docker run -d --name "$COLL" --network "$NET" --cpus "$cpus" --memory 1g \
      -v "$cfg:/etc/agentward/loadtest.yaml:ro" \
      -v "$REPO/collector/policy:/etc/agentward/policy:ro" \
      "$IMAGE" --config=/etc/agentward/loadtest.yaml >/dev/null
    sleep 2

    set_attrs "$sc"
    for i in $(seq 1 "$SENDERS"); do
      docker run -d --name "$TG-$i" --network "$NET" "$TGEN" traces \
        --otlp-endpoint "$COLL:4317" --otlp-insecure \
        --duration "$((DURATION + WARMUP + 5))s" --rate 0 --workers "$WORKERS" \
        --service loadtest "${ATTRS[@]}" >/dev/null
    done

    sleep "$WARMUP"
    cid=$(docker inspect -f '{{.Id}}' "$COLL")
    s0=$(metric otelcol_exporter_sent_spans); r0=$(metric otelcol_receiver_refused_spans)
    u0=$(cpu_usec "$cid"); t0=$(date +%s.%N)
    sleep "$DURATION"
    s1=$(metric otelcol_exporter_sent_spans); r1=$(metric otelcol_receiver_refused_spans)
    u1=$(cpu_usec "$cid"); t1=$(date +%s.%N)

    rate=$(awk -v a="$s0" -v b="$s1" -v x="$t0" -v y="$t1" 'BEGIN {printf "%d", (b - a) / (y - x)}')
    cpu=$(awk -v a="$u0" -v b="$u1" -v x="$t0" -v y="$t1" 'BEGIN {if (b > 0) printf "%d", (b - a) / 1e6 / (y - x) * 100; else print "n/a"}')
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$sc" "$cpus" "$SENDERS" "$rate" "$((r1 - r0))" "$cpu" | tee -a "$OUT"
    stop_senders
  done
done
