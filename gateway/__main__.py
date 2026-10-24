"""CLI: serve the AgentWard MCP gateway over stdio.

    python -m gateway --config gateway/example-config.yaml

stdout carries the MCP protocol, so all logs go to stderr.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import anyio


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m gateway",
                                description="AgentWard MCP gateway (stdio)")
    p.add_argument("--config", required=True, help="path to the gateway YAML config")
    p.add_argument("--otlp-endpoint", default=os.environ.get("AGENTWARD_OTLP_ENDPOINT"),
                   help="OTLP/HTTP traces endpoint, e.g. http://localhost:4318/v1/traces "
                        "(default: $AGENTWARD_OTLP_ENDPOINT; no export when unset)")
    p.add_argument("--log-level", default="WARNING")
    args = p.parse_args(argv)

    logging.basicConfig(stream=sys.stderr, level=args.log_level.upper(),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # Presidio is chatty at INFO; keep stderr readable.
    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

    from mcp import stdio_server
    from opentelemetry import trace

    from gateway.config import load_config
    from gateway.server import Gateway

    config = load_config(args.config)
    tracer = None
    if args.otlp_endpoint:
        from sdk.instrumentation import configure_tracing
        tracer = configure_tracing(config.service_name, endpoint=args.otlp_endpoint)

    server = Gateway(config, tracer=tracer).build_server()

    async def serve() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    try:
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
