"""Entry point for the demo container.

Waits until the Taintward collector accepts connections, then runs the
breach simulator against it. The collector image is distroless (no shell,
no curl), so the wait lives here instead of in a compose healthcheck.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from urllib.parse import urlparse

ENDPOINT = os.environ.get("COLLECTOR_ENDPOINT", "http://taintward-collector:4319/v1/traces")
TIMEOUT_S = float(os.environ.get("COLLECTOR_WAIT_SECONDS", "60"))


def wait_for(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def main() -> int:
    url = urlparse(ENDPOINT)
    host, port = url.hostname or "localhost", url.port or 4319
    print(f"waiting for collector at {host}:{port} ...", flush=True)
    if not wait_for(host, port, TIMEOUT_S):
        print(f"collector not reachable after {TIMEOUT_S:.0f}s", file=sys.stderr)
        return 1
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hr_bot", "breach_simulator.py")
    os.execvp(sys.executable, [sys.executable, script, "--endpoint", ENDPOINT, *sys.argv[1:]])
    return 0  # not reached


if __name__ == "__main__":
    raise SystemExit(main())
