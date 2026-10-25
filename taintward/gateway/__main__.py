"""CLI: serve the Taintward MCP gateway over stdio or streamable HTTP.

    python -m taintward.gateway --config taintward/gateway/example-config.yaml
    python -m taintward.gateway --config taintward/gateway/example-config.yaml --listen 0.0.0.0:8811

Over stdio, stdout carries the MCP protocol, so all logs go to stderr.
Over HTTP the MCP endpoint is /mcp and /healthz answers 200 for probes.
Set TAINTWARD_GATEWAY_TOKEN to require "Authorization: Bearer <token>".
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import anyio


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m taintward.gateway",
                                description="Taintward MCP gateway (stdio or streamable HTTP)")
    p.add_argument("--config", required=True, help="path to the gateway YAML config")
    p.add_argument("--listen", metavar="HOST:PORT", default=None,
                   help="serve streamable HTTP on HOST:PORT (e.g. 0.0.0.0:8811) "
                        "instead of stdio")
    p.add_argument("--shutdown-timeout", type=float, default=None,
                   help="HTTP mode: seconds to let in flight requests finish on "
                        "SIGTERM (default 25)")
    p.add_argument("--otlp-endpoint", default=os.environ.get("TAINTWARD_OTLP_ENDPOINT"),
                   help="OTLP/HTTP traces endpoint, e.g. http://localhost:4318/v1/traces "
                        "(default: $TAINTWARD_OTLP_ENDPOINT; no export when unset)")
    p.add_argument("--log-level", default="WARNING")
    args = p.parse_args(argv)

    logging.basicConfig(stream=sys.stderr, level=args.log_level.upper(),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # Presidio is chatty at INFO; keep stderr readable.
    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

    from opentelemetry import trace

    from taintward.gateway.config import load_config
    from taintward.gateway.server import Gateway

    listen = None
    if args.listen:
        from taintward.gateway.http import parse_listen
        try:
            listen = parse_listen(args.listen)
        except ValueError as exc:
            p.error(str(exc))

    config = load_config(args.config)
    tracer = None
    if args.otlp_endpoint:
        from taintward.sdk.instrumentation import configure_tracing
        tracer = configure_tracing(config.service_name, endpoint=args.otlp_endpoint)

    gateway = Gateway(config, tracer=tracer)

    try:
        if listen is not None:
            from taintward.gateway.http import DEFAULT_SHUTDOWN_TIMEOUT, serve_http
            host, port = listen
            token = os.environ.get("TAINTWARD_GATEWAY_TOKEN") or None
            if token is None and host not in ("127.0.0.1", "localhost", "::1"):
                logging.getLogger("taintward.gateway").warning(
                    "serving on %s without TAINTWARD_GATEWAY_TOKEN: anyone who can "
                    "reach the port can call the tools", host)
            serve_http(gateway, host, port, token=token,
                       shutdown_timeout=(args.shutdown_timeout
                                         if args.shutdown_timeout is not None
                                         else DEFAULT_SHUTDOWN_TIMEOUT),
                       log_level=args.log_level)
        else:
            from mcp import stdio_server

            server = gateway.build_server()

            async def serve() -> None:
                async with stdio_server() as (read_stream, write_stream):
                    await server.run(read_stream, write_stream,
                                     server.create_initialization_options())

            anyio.run(serve)
    except KeyboardInterrupt:
        pass
    finally:
        shutdown = getattr(trace.get_tracer_provider(), "shutdown", None)
        if shutdown is not None:
            shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
