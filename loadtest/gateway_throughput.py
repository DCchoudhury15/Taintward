"""MCP gateway throughput: tool calls per second over stdio and HTTP.

The gateway fronts the example HR server (taintward/gateway/examples/hr_server.py).
Two tools are called in a loop:

* ``clean``:     list_departments, no sensitive data
* ``sensitive``: get_employee, whose result carries an SSN and an AWS key
                 (scanned, masked before the agent sees it, session tainted)

Modes:

* ``stdio``: one gateway process, one MCP session, C calls in flight.
* ``http``:  K gateway processes (``--replicas``) each serving streamable HTTP
             on its own local port, and N client sessions spread over them
             round robin. This is what several replicas behind a load
             balancer look like, without the load balancer.

Usage (from the repo root):

    .venv/bin/python loadtest/gateway_throughput.py
    .venv/bin/python loadtest/gateway_throughput.py --modes http --clients 1 4 8 --replicas 1 2
    .venv/bin/python loadtest/gateway_throughput.py --url http://gw.example:8811/mcp --token ...

Writes loadtest/results/gateway-<label>.json and .md.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import anyio

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("TAINTWARD_ALLOW_DEMO_KEY", "1")

TOOLS = {"clean": ("list_departments", {}), "sensitive": ("get_employee", {"employee_id": "E100"})}

CONFIG = """\
service_name: taintward-gateway-loadtest
upstreams:
  - name: hr
    command: python
    args: ["-m", "taintward.gateway.examples.hr_server"]
    cwd: {root}
    env:
      TAINTWARD_HR_OUTBOX: {outbox}
defaults:
  destination: external
  mode: redact
tools:
  - match: "get_*"
    destination: internal
  - match: "list_*"
    destination: internal
"""


def write_config(tmp: Path) -> Path:
    p = tmp / "gateway.yaml"
    p.write_text(CONFIG.format(root=ROOT, outbox=tmp / "outbox.jsonl"))
    return p


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def call_loop(client, tool: str, args: dict, seconds: float, inflight: int) -> int:
    count = 0
    end = time.perf_counter() + seconds

    async def worker() -> None:
        nonlocal count
        while time.perf_counter() < end:
            await client.call_tool(tool, args)
            count += 1

    async with anyio.create_task_group() as tg:
        for _ in range(inflight):
            tg.start_soon(worker)
    return count


async def run_stdio(cfg: Path, kind: str, inflight: int, seconds: float) -> float:
    from mcp import Client, StdioServerParameters

    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "taintward.gateway", "--config", str(cfg)], cwd=str(ROOT),
                                   env={**os.environ})
    tool, args = TOOLS[kind]
    async with Client(params, read_timeout_seconds=120) as client:
        await client.call_tool(tool, args)  # warm up (Presidio load happens at start)
        t0 = time.perf_counter()
        n = await call_loop(client, tool, args, seconds, inflight)
        return n / (time.perf_counter() - t0)


def http_client(url: str, token: str | None):
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    headers = {"Authorization": f"Bearer {token}"} if token else None
    return Client(streamable_http_client(url, http_client=create_mcp_http_client(headers=headers)),
                  read_timeout_seconds=120)


async def run_http(urls: list[str], token: str | None, kind: str, clients: int,
                   seconds: float) -> float:
    tool, args = TOOLS[kind]
    counts = [0] * clients
    ready = anyio.Event()
    started = [0]

    async def one(i: int) -> None:
        async with http_client(urls[i % len(urls)], token) as client:
            await client.call_tool(tool, args)  # warm up and open the session
            started[0] += 1
            if started[0] == clients:
                ready.set()
            await ready.wait()
            counts[i] = await call_loop(client, tool, args, seconds, 1)

    t0 = [0.0]

    async def clock() -> None:
        await ready.wait()
        t0[0] = time.perf_counter()

    async with anyio.create_task_group() as tg:
        tg.start_soon(clock)
        for i in range(clients):
            tg.start_soon(one, i)
    return sum(counts) / (time.perf_counter() - t0[0])


def start_http_gateways(cfg: Path, n: int, token: str | None) -> tuple[list, list[str]]:
    procs, urls = [], []
    env = {**os.environ}
    if token:
        env["TAINTWARD_GATEWAY_TOKEN"] = token
    for _ in range(n):
        port = free_port()
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "taintward.gateway", "--config", str(cfg), "--listen", f"127.0.0.1:{port}"],
            cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        urls.append(f"http://127.0.0.1:{port}/mcp")
    import httpx
    deadline = time.time() + 120
    for u in urls:
        health = u.replace("/mcp", "/healthz")
        while True:
            try:
                if httpx.get(health, timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.time() > deadline:
                raise RuntimeError(f"gateway at {u} did not come up")
            time.sleep(0.5)
    return procs, urls


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--modes", nargs="*", default=["stdio", "http"])
    ap.add_argument("--inflight", type=int, nargs="*", default=[1, 4],
                    help="stdio: calls in flight on the one session")
    ap.add_argument("--clients", type=int, nargs="*", default=[1, 4, 8],
                    help="http: concurrent client sessions")
    ap.add_argument("--replicas", type=int, nargs="*", default=[1, 2, 4],
                    help="http: local gateway processes")
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--url", default=None, help="http: test this gateway instead of starting local ones")
    ap.add_argument("--token", default=os.environ.get("TAINTWARD_GATEWAY_TOKEN"))
    ap.add_argument("--label", default="current")
    args = ap.parse_args()

    rows = []
    with tempfile.TemporaryDirectory() as td:
        cfg = write_config(Path(td))
        if "stdio" in args.modes:
            for kind in TOOLS:
                for c in args.inflight:
                    rate = anyio.run(run_stdio, cfg, kind, c, args.seconds)
                    rows.append({"mode": "stdio", "tool": kind, "replicas": 1, "concurrency": c,
                                 "calls_per_s": round(rate, 1)})
                    print(f"stdio {kind:9s} inflight={c:<3d} {rate:8.1f} calls/s", flush=True)
        if "http" in args.modes:
            replica_sets = [None] if args.url else args.replicas
            for k in replica_sets:
                procs, urls = ([], [args.url]) if args.url else start_http_gateways(cfg, k, args.token)
                try:
                    for kind in TOOLS:
                        for c in args.clients:
                            rate = anyio.run(run_http, urls, args.token, kind, c, args.seconds)
                            rows.append({"mode": "http", "tool": kind, "replicas": k or "remote",
                                         "concurrency": c, "calls_per_s": round(rate, 1)})
                            print(f"http  {kind:9s} replicas={k} clients={c:<3d} {rate:8.1f} calls/s",
                                  flush=True)
                finally:
                    for p in procs:
                        p.terminate()
                    for p in procs:
                        p.wait(timeout=30)

    meta = {"label": args.label, "python": platform.python_version(), "cpus": os.cpu_count(),
            "seconds_per_point": args.seconds, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    out = ROOT / "loadtest" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"gateway-{args.label}.json").write_text(json.dumps({"meta": meta, "rows": rows}, indent=2) + "\n")
    lines = [f"# Gateway throughput ({args.label})", "",
             f"{meta['time']}, Python {meta['python']}, {meta['cpus']} CPUs, "
             f"{args.seconds:g} s per point. Upstream: taintward/gateway/examples/hr_server.py over stdio.", "",
             "| mode | tool | gateway processes | concurrency | calls/s |", "|---|---|---|---|---|"]
    lines += [f"| {r['mode']} | {r['tool']} | {r['replicas']} | {r['concurrency']} | {r['calls_per_s']:.0f} |"
              for r in rows]
    (out / f"gateway-{args.label}.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[4:]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
