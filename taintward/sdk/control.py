"""Get the tool policy from a Taintward control plane (taintward/control).

    ward = ward_from_control()          # TAINTWARD_CONTROL_URL / _TOKEN
    ward = ward_from_control(refresh_seconds=60)   # and keep it current

Environment:
    TAINTWARD_CONTROL_URL              e.g. https://control.example.com
    TAINTWARD_CONTROL_TOKEN            an ``agent`` token of your tenant
    TAINTWARD_CONTROL_CACHE            file for the last policy received, used
                                       when the control plane cannot be reached
    TAINTWARD_CONTROL_REFRESH_SECONDS  check for a new policy this often

When neither the control plane nor the cache answers, the Ward starts with
an empty map: every tool is ``external``, so everything is redacted. That
is the safe side; nothing is sent raw because the policy was missing.

The control plane decides which tools count as ``internal`` (unredacted),
so its admin tokens are as sensitive as the code that holds the map.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("taintward.sdk")

_LOCAL = ("localhost", "127.0.0.1", "::1")


class ControlError(RuntimeError):
    pass


class ControlClient:
    def __init__(self, url: str | None = None, token: str | None = None, *,
                 cache: str | os.PathLike | None = None, timeout: float = 5.0) -> None:
        self.url = (url or os.environ.get("TAINTWARD_CONTROL_URL", "")).rstrip("/")
        self.token = token or os.environ.get("TAINTWARD_CONTROL_TOKEN", "")
        if not self.url or not self.token:
            raise ControlError("set TAINTWARD_CONTROL_URL and TAINTWARD_CONTROL_TOKEN "
                               "(or pass url= and token=)")
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https"):
            raise ControlError("TAINTWARD_CONTROL_URL must be http:// or https://")
        if parts.scheme == "http" and parts.hostname not in _LOCAL:
            log.warning("taintward: the control plane URL is plain http; the token and policy "
                        "travel unencrypted. Use https outside a private network.")
        cache = cache if cache is not None else os.environ.get("TAINTWARD_CONTROL_CACHE") or None
        self.cache = Path(cache) if cache else None
        self.timeout = timeout
        self.etag = ""
        self.last: dict | None = None

    def fetch(self) -> dict:
        """The tenant's policy document ({"version", "etag", "policy", ...}).
        Sends the last ETag, so an unchanged policy costs a 304."""
        req = urllib.request.Request(self.url + "/v1/policy", headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/json",
            **({"If-None-Match": f'"{self.etag}"'} if self.etag and self.last else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                doc = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 304 and self.last is not None:
                return self.last
            raise ControlError(f"control plane answered {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ControlError(f"cannot reach the control plane: {exc}") from None
        if not isinstance(doc, dict) or not isinstance(doc.get("policy"), dict):
            raise ControlError("control plane sent no policy")
        self.etag, self.last = str(doc.get("etag") or ""), doc
        if self.cache:
            try:
                self.cache.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.cache.with_name(self.cache.name + ".tmp")
                tmp.write_text(json.dumps(doc), encoding="utf-8")
                os.replace(tmp, self.cache)
            except OSError as exc:
                log.warning("taintward: could not write the policy cache %s: %s", self.cache, exc)
        return doc

    def load(self) -> dict | None:
        """fetch(), else the cached policy, else None."""
        try:
            return self.fetch()
        except ControlError as exc:
            err = exc
        if self.cache and self.cache.is_file():
            try:
                doc = json.loads(self.cache.read_text(encoding="utf-8"))
                log.warning("taintward: %s; using the cached policy v%s", err, doc.get("version"))
                return doc
            except (OSError, ValueError):
                pass
        log.warning("taintward: %s and no cached policy; every tool is treated as external", err)
        return None


def ward_kwargs(policy: dict) -> dict[str, Any]:
    return {"default_destination": policy.get("default_destination") or "external",
            "default_jurisdiction": policy.get("default_jurisdiction") or "",
            "llm_jurisdiction": policy.get("llm_jurisdiction") or ""}


def ward_from_control(url: str | None = None, token: str | None = None, *,
                      refresh_seconds: float | None = None,
                      cache: str | os.PathLike | None = None, **ward_options: Any):
    """A Ward whose tool map comes from the control plane. ``ward_options``
    are the other Ward settings (tracer, placeholders, ...). With
    ``refresh_seconds`` (default TAINTWARD_CONTROL_REFRESH_SECONDS) a
    background thread applies new policy versions as they appear."""
    from taintward.sdk.integrations import Ward

    client = ControlClient(url, token, cache=cache)
    doc = client.load()
    policy = (doc or {}).get("policy") or {}
    ward = Ward(policy.get("destinations") or {}, **ward_kwargs(policy), **ward_options)
    ward.policy_version = (doc or {}).get("version")
    ward.control = client
    if refresh_seconds is None:
        env = os.environ.get("TAINTWARD_CONTROL_REFRESH_SECONDS", "").strip()
        refresh_seconds = float(env) if env else None
    if refresh_seconds:
        _start_refresh(ward, client, float(refresh_seconds))
    return ward


def refresh_ward(ward, client: ControlClient | None = None) -> bool:
    """Apply the newest policy to ``ward``; True when it changed."""
    client = client or ward.control
    before = client.etag
    try:
        doc = client.fetch()
    except ControlError as exc:
        log.warning("taintward: policy refresh failed, keeping v%s: %s", ward.policy_version, exc)
        return False
    if client.etag == before and ward.policy_version is not None:
        return False
    ward.apply_policy(doc["policy"])
    ward.policy_version = doc.get("version")
    log.info("taintward: tool policy v%s applied", ward.policy_version)
    return True


def _start_refresh(ward, client: ControlClient, every: float) -> None:
    stop = threading.Event()

    def loop() -> None:
        while not stop.wait(max(every, 1.0)):
            refresh_ward(ward, client)

    threading.Thread(target=loop, name="taintward-policy-refresh", daemon=True).start()
    ward.stop_refresh = stop.set
