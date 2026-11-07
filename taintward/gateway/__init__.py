"""Taintward MCP gateway: enforce Taintward policy on MCP tool calls with no
changes to agent code. See docs/mcp-gateway.md.

The config reader needs only PyYAML, so tools that read a gateway config
(taintward-audit --gateway-config) work without the MCP SDK. The server is
loaded on first use of ``Gateway`` or ``BLOCKED_ERROR_CODE``."""

from taintward.gateway.config import GatewayConfig, load_config, parse_config

__all__ = ["BLOCKED_ERROR_CODE", "Gateway", "GatewayConfig", "load_config", "parse_config"]

_FROM_SERVER = ("BLOCKED_ERROR_CODE", "Gateway")


def __getattr__(name: str):
    if name in _FROM_SERVER:
        from taintward.gateway import server

        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
