"""Gateway config: upstream MCP servers and per-tool policy settings.

The config is a YAML file. See ``taintward/gateway/example-config.yaml`` and
``docs/mcp-gateway.md`` for the full reference.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from taintward.sdk.destinations import (
    DEST_EXTERNAL,
    DEST_INTERNAL,
    DEST_LLM,
    DEST_LOG,
    DEST_RAG,
)

VALID_DESTINATIONS = frozenset({DEST_INTERNAL, DEST_EXTERNAL, DEST_LLM, DEST_LOG, DEST_RAG})

MODE_REDACT = "redact"
MODE_BLOCK = "block"
MODE_AUDIT = "audit"
VALID_MODES = frozenset({MODE_REDACT, MODE_BLOCK, MODE_AUDIT})

# What to do when an upstream tool's description or schema changes (gap G2).
TOOL_CHANGE_WARN = "warn"
TOOL_CHANGE_HIDE = "hide"
VALID_TOOL_CHANGES = frozenset({TOOL_CHANGE_WARN, TOOL_CHANGE_HIDE})

_CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

logger = logging.getLogger("taintward.gateway")


class ConfigError(ValueError):
    """Raised for an invalid gateway config."""


@dataclass
class UpstreamConfig:
    """One upstream MCP server. Exactly one of ``command`` or ``url`` is set."""

    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    prefix: str = ""
    # Test hook: an in-process mcp Server / MCPServer object. Not settable
    # from YAML.
    server_object: Any = None


@dataclass(frozen=True)
class ToolPolicy:
    """The resolved policy for one tool."""

    destination: str
    jurisdiction: str
    mode: str
    redact_results: bool
    # Top-level argument names that are neither scanned nor redacted (for
    # example the "to" address of an email tool). Use sparingly.
    passthrough_args: frozenset[str] = frozenset()


@dataclass
class ToolRule:
    match: str
    upstream: str | None = None
    destination: str | None = None
    jurisdiction: str | None = None
    mode: str | None = None
    redact_results: bool | None = None
    passthrough_args: frozenset[str] | None = None

    def matches(self, tool: str, upstream: str) -> bool:
        if self.upstream is not None and self.upstream != upstream:
            return False
        return fnmatch.fnmatchcase(tool, self.match)


@dataclass
class GatewayConfig:
    upstreams: list[UpstreamConfig]
    rules: list[ToolRule] = field(default_factory=list)
    default: ToolPolicy = ToolPolicy(
        destination=DEST_EXTERNAL, jurisdiction="", mode=MODE_REDACT, redact_results=True,
    )
    service_name: str = "taintward-mcp-gateway"
    # Where session taint lives: "memory" (one process) or "redis://..."
    # (shared by several replicas). TAINTWARD_SESSION_STORE overrides it.
    session_store: str = "memory"
    # Seconds a session's taint is kept after its last use.
    session_ttl: float = 24 * 3600.0
    # Gap G2: exposed tool name -> expected fingerprint (``tool_fingerprint``).
    # A tool without a pin is compared with the first version seen.
    tool_pins: dict[str, str] = field(default_factory=dict)
    # "warn": log and record a span; "hide": also stop exposing the tool.
    on_tool_change: str = TOOL_CHANGE_WARN
    # Gap G4, stdio: a client name whose taint is kept across sessions
    # (useful with a Redis session store). Over HTTP the name comes from
    # the client's token (TAINTWARD_GATEWAY_TOKENS).
    client: str | None = None

    def policy_for(self, tool: str, upstream: str = "") -> ToolPolicy:
        """Resolve a tool's policy. The first matching rule wins; fields it
        leaves out fall back to ``defaults``. Unknown tools get the defaults
        (destination ``external`` unless configured otherwise)."""
        for rule in self.rules:
            if rule.matches(tool, upstream):
                return ToolPolicy(
                    destination=rule.destination or self.default.destination,
                    jurisdiction=(rule.jurisdiction if rule.jurisdiction is not None
                                  else self.default.jurisdiction),
                    mode=rule.mode or self.default.mode,
                    redact_results=(rule.redact_results if rule.redact_results is not None
                                    else self.default.redact_results),
                    passthrough_args=(rule.passthrough_args if rule.passthrough_args is not None
                                      else self.default.passthrough_args),
                )
        return self.default


def _check_dest(value: Any, where: str) -> str | None:
    if value is None:
        return None
    if value not in VALID_DESTINATIONS:
        raise ConfigError(f"{where}: destination {value!r} is not one of "
                          f"{sorted(VALID_DESTINATIONS)}")
    return value


def _check_mode(value: Any, where: str) -> str | None:
    if value is None:
        return None
    if value not in VALID_MODES:
        raise ConfigError(f"{where}: mode {value!r} is not one of {sorted(VALID_MODES)}")
    return value


def _names(value: Any, where: str) -> frozenset[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ConfigError(f"{where}: passthrough_args must be a list of argument names")
    return frozenset(str(v) for v in value)


def _resolve_command(command: str) -> str:
    # "python" / "python3" mean "the interpreter running the gateway", so the
    # upstream shares the gateway's virtualenv.
    if command in {"python", "python3"}:
        return sys.executable
    return command


def parse_config(data: dict[str, Any], base_dir: str | os.PathLike | None = None) -> GatewayConfig:
    """Build a :class:`GatewayConfig` from an already-parsed YAML mapping.

    ``base_dir`` is the directory relative upstream ``cwd`` values resolve
    against (the config file's directory when loaded from a file).
    """
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    base = Path(base_dir) if base_dir is not None else Path.cwd()

    raw_ups = data.get("upstreams") or []
    if not isinstance(raw_ups, list) or not raw_ups:
        raise ConfigError("config needs a non-empty 'upstreams' list")
    upstreams: list[UpstreamConfig] = []
    seen: set[str] = set()
    for i, u in enumerate(raw_ups):
        where = f"upstreams[{i}]"
        if not isinstance(u, dict):
            raise ConfigError(f"{where} must be a mapping")
        name = str(u.get("name") or f"upstream{i}")
        if name in seen:
            raise ConfigError(f"{where}: duplicate upstream name {name!r}")
        seen.add(name)
        command, url = u.get("command"), u.get("url")
        if bool(command) == bool(url):
            raise ConfigError(f"{where}: set exactly one of 'command' or 'url'")
        cwd = u.get("cwd")
        if cwd is not None:
            cwd = str((base / cwd).resolve())
        upstreams.append(UpstreamConfig(
            name=name,
            command=_resolve_command(str(command)) if command else None,
            args=[str(a) for a in (u.get("args") or [])],
            env={str(k): str(v) for k, v in (u.get("env") or {}).items()},
            cwd=cwd,
            url=str(url) if url else None,
            prefix=str(u.get("prefix") or ""),
        ))

    d = data.get("defaults") or {}
    default = ToolPolicy(
        destination=_check_dest(d.get("destination"), "defaults") or DEST_EXTERNAL,
        jurisdiction=str(d.get("jurisdiction") or ""),
        mode=_check_mode(d.get("mode"), "defaults") or MODE_REDACT,
        redact_results=bool(d.get("redact_results", True)),
        passthrough_args=_names(d.get("passthrough_args"), "defaults") or frozenset(),
    )

    rules: list[ToolRule] = []
    for i, r in enumerate(data.get("tools") or []):
        where = f"tools[{i}]"
        if not isinstance(r, dict) or not r.get("match"):
            raise ConfigError(f"{where} needs a 'match' glob")
        if r.get("upstream") and str(r["upstream"]) not in seen:
            raise ConfigError(f"{where}: upstream {r['upstream']!r} is not in 'upstreams'")
        rr = r.get("redact_results")
        rules.append(ToolRule(
            match=str(r["match"]),
            upstream=str(r["upstream"]) if r.get("upstream") else None,
            destination=_check_dest(r.get("destination"), where),
            jurisdiction=str(r["jurisdiction"]) if r.get("jurisdiction") is not None else None,
            mode=_check_mode(r.get("mode"), where),
            redact_results=bool(rr) if rr is not None else None,
            passthrough_args=_names(r.get("passthrough_args"), where),
        ))
        rule = rules[-1]
        if (len(upstreams) > 1 and rule.upstream is None
                and (rule.destination == DEST_INTERNAL or rule.passthrough_args)):
            # Gap G3: any upstream can claim a tool name this rule trusts.
            logger.warning("%s (match %r) grants %s without 'upstream:'; a tool of that "
                           "name from any upstream gets it. Pin the rule to an upstream.",
                           where, rule.match,
                           "internal" if rule.destination == DEST_INTERNAL
                           else "passthrough_args")

    store = str(data.get("session_store") or "memory").strip()
    if not (store in ("memory", "memory://") or store.startswith(("redis://", "rediss://", "unix://"))):
        raise ConfigError(f"session_store {store!r} must be 'memory' or a redis:// url")
    try:
        ttl = float(data.get("session_ttl") or 24 * 3600.0)
    except (TypeError, ValueError):
        raise ConfigError("session_ttl must be a number of seconds") from None
    if ttl <= 0:
        raise ConfigError("session_ttl must be positive")

    pins = data.get("tool_pins") or {}
    if not isinstance(pins, dict):
        raise ConfigError("tool_pins must map tool names to fingerprints")
    on_change = str(data.get("on_tool_change") or TOOL_CHANGE_WARN)
    if on_change not in VALID_TOOL_CHANGES:
        raise ConfigError(f"on_tool_change {on_change!r} is not one of "
                          f"{sorted(VALID_TOOL_CHANGES)}")
    client = data.get("client")
    if client is not None and not _CLIENT_NAME_RE.match(str(client)):
        raise ConfigError("client must be 1 to 64 letters, digits, '.', '_' or '-'")

    return GatewayConfig(
        upstreams=upstreams,
        rules=rules,
        default=default,
        service_name=str(data.get("service_name") or "taintward-mcp-gateway"),
        session_store=store,
        session_ttl=ttl,
        tool_pins={str(k): str(v) for k, v in pins.items()},
        on_tool_change=on_change,
        client=str(client) if client is not None else None,
    )


def parse_client_tokens(spec: str | None) -> dict[str, str]:
    """``TAINTWARD_GATEWAY_TOKENS``: ``name:token,name2:token2`` -> {token: name}.

    Each client gets its own token, and its taint is kept per client name
    as well as per session (gap G4)."""
    out: dict[str, str] = {}
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        name, sep, token = item.partition(":")
        if not sep or not token or not _CLIENT_NAME_RE.match(name):
            raise ConfigError("TAINTWARD_GATEWAY_TOKENS entries are name:token, with a name "
                              "of letters, digits, '.', '_' or '-'")
        if token in out:
            raise ConfigError("TAINTWARD_GATEWAY_TOKENS: two clients share a token")
        out[token] = name
    return out


def load_config(path: str | os.PathLike) -> GatewayConfig:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return parse_config(data, base_dir=p.parent)
