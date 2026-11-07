"""Control plane configuration: the data directory and the tenants.

YAML (needs PyYAML) or JSON::

    data_dir: /var/lib/taintward-control
    max_body_bytes: 8388608
    tenants:
      acme:
        home: [eu]                # home jurisdictions (cross-border marks)
        tokens:
          - {name: app, role: agent, sha256: 9f86d0...}
          - {name: dpo, role: reader, sha256: 2c26b4...}
          - {name: ops, role: admin, sha256: fcde2b...}

Only the SHA-256 of each token is stored (``taintward-control new-token``
prints a token and its hash). Roles:

    agent   pull the policy, upload spans (what an app needs)
    reader  read the policy, its history, reports, evidence; run audits
    admin   everything, including changing the policy
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from taintward.evidence.shards import check_tenant

ROLES: dict[str, frozenset[str]] = {
    "agent": frozenset({"policy:read", "traces:write"}),
    "reader": frozenset({"policy:read", "report:read", "evidence:read", "audit:run"}),
}
ROLES["admin"] = frozenset().union(*ROLES.values(), {"policy:write"})

DEFAULT_MAX_BODY = 8 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Principal:
    """Who is calling: a tenant, the token's name and its role."""

    tenant: str
    name: str
    role: str

    def can(self, permission: str) -> bool:
        return permission in ROLES[self.role]


@dataclass
class Tenant:
    name: str
    home: tuple[str, ...] = ()


@dataclass
class ControlConfig:
    data_dir: Path
    tenants: dict[str, Tenant] = field(default_factory=dict)
    tokens: dict[str, Principal] = field(default_factory=dict)  # sha256 hex -> principal
    max_body_bytes: int = DEFAULT_MAX_BODY

    def principal(self, token: str) -> Principal | None:
        if not token:
            return None
        return self.tokens.get(hash_token(token))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> tuple[str, str]:
    """(token, sha256) for a new random token."""
    token = "twc_" + secrets.token_urlsafe(32)
    return token, hash_token(token)


def parse_config(data: Any, base_dir: Path | None = None) -> ControlConfig:
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    base = base_dir or Path.cwd()
    raw_dir = data.get("data_dir")
    if not raw_dir:
        raise ConfigError("config needs 'data_dir'")
    data_dir = Path(str(raw_dir))
    if not data_dir.is_absolute():
        data_dir = (base / data_dir).resolve()
    try:
        max_body = int(data.get("max_body_bytes") or DEFAULT_MAX_BODY)
    except (TypeError, ValueError):
        raise ConfigError("max_body_bytes must be a number") from None
    if max_body <= 0:
        raise ConfigError("max_body_bytes must be positive")

    raw_tenants = data.get("tenants")
    if not isinstance(raw_tenants, dict) or not raw_tenants:
        raise ConfigError("config needs a non-empty 'tenants' mapping")
    tenants: dict[str, Tenant] = {}
    tokens: dict[str, Principal] = {}
    for tname, t in raw_tenants.items():
        tname = str(tname)
        try:
            check_tenant(tname)
        except ValueError as exc:
            raise ConfigError(str(exc)) from None
        if not isinstance(t, dict):
            raise ConfigError(f"tenants.{tname} must be a mapping")
        home = t.get("home") or []
        if isinstance(home, str):
            home = [h for h in home.split(",") if h.strip()]
        tenants[tname] = Tenant(tname, tuple(str(h).strip().lower() for h in home))
        toks = t.get("tokens") or []
        if not isinstance(toks, list) or not toks:
            raise ConfigError(f"tenants.{tname} needs a non-empty 'tokens' list")
        for i, tok in enumerate(toks):
            where = f"tenants.{tname}.tokens[{i}]"
            if not isinstance(tok, dict):
                raise ConfigError(f"{where} must be a mapping")
            role = str(tok.get("role") or "")
            if role not in ROLES:
                raise ConfigError(f"{where}: role must be one of {sorted(ROLES)}")
            digest = str(tok.get("sha256") or "").strip().lower()
            if not _HEX64.match(digest):
                raise ConfigError(f"{where}: sha256 must be 64 hex characters "
                                  "(the hash of the token, not the token)")
            if digest in tokens:
                raise ConfigError(f"{where}: the same token is listed twice")
            tokens[digest] = Principal(tname, str(tok.get("name") or f"token{i}"), role)
    return ControlConfig(data_dir, tenants, tokens, max_body)


def load_config(path: str | os.PathLike) -> ControlConfig:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError:  # pragma: no cover
            raise ConfigError("a YAML config needs PyYAML (pip install 'taintward[control]'); "
                              "or use a .json file") from None
        data = yaml.safe_load(text)
    return parse_config(data, p.parent)
