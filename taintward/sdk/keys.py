"""Key providers and rotation for the FPE key and the vault key.

Taintward uses two secret keys:

    fpe    AES key for FF1, makes the reversible tokens (taintward/sdk/redact.py)
    vault  AES-GCM key that seals originals in the vault (taintward/sdk/vault.py)

Each purpose has a key ring: one active key that is used for new work, and
older keys that are only used to read what they made. Where the rings come
from is set with TAINTWARD_KEYS:

    unset or "env"           TAINTWARD_FPE_KEY / TAINTWARD_VAULT_KEY (one key
                             each), plus TAINTWARD_VAULT_KEY_PREVIOUS (comma
                             separated hex) for vault keys being rotated out
    "file:<path>"            a JSON key ring file (format below)
    "vault-kv:<mount>/<path>"  the same JSON stored in HashiCorp Vault KV v2,
                             read with VAULT_ADDR and VAULT_TOKEN

TAINTWARD_FPE_KEY and TAINTWARD_VAULT_KEY, when set, still win over the ring
for the active key, so an existing setup keeps working unchanged.

Key ring JSON:

    {
      "kms": "aws-kms:alias/taintward",          optional default for wrapped keys
      "fpe":   {"active": "2026-10",
                "keys": {"2026-10": {"wrapped": "<base64>"},
                         "2026-04": "<hex>"}},
      "vault": {"active": "v2", "keys": {"v2": {"hex": "<hex>"}}}
    }

A key is plain hex (a string or {"hex": ...}) or wrapped by a KMS
({"wrapped": ..., "kms": ...}, "kms" falling back to the top level one).
Wrapped keys are unwrapped once, when the ring is loaded:

    aws-kms:<key id, arn or alias>    AWS KMS Decrypt (boto3, AWS_* settings)
    gcp-kms:projects/.../cryptoKeys/<k>  Google Cloud KMS (google-cloud-kms)
    vault-transit:[<mount>/]<key>    HashiCorp Vault Transit decrypt

AWS and GCP wraps are bound to the purpose ("taintward-key" = "fpe" or
"vault" as encryption context / additional data), so a wrapped vault key
cannot be passed off as an FPE key.

The taintward-keys command makes and rotates rings: generate, rotate,
retire, show and reseal (re-encrypt vault rows under the active key).
See docs/key-management.md.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

PURPOSES = ("fpe", "vault")
_KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class KeyConfigError(ValueError):
    """A key ring could not be loaded or is invalid. Never holds key bytes."""


def key_id_for(key: bytes) -> str:
    """Default id of a key: a short hash, the same one Redactor has always used."""
    return "k" + hashlib.sha256(b"taintward-key-id" + key).hexdigest()[:8]


def parse_hex_key(key_hex: str, what: str) -> bytes:
    try:
        key = bytes.fromhex(key_hex.strip())
    except ValueError:
        raise KeyConfigError(f"{what} must be hex") from None
    if len(key) not in (16, 24, 32):
        raise KeyConfigError(f"{what} must be 16, 24 or 32 bytes (32, 48 or 64 hex chars)")
    return key


@dataclass
class KeyRing:
    """The keys of one purpose: ``active`` makes new work, the rest only read."""

    purpose: str
    active: str
    keys: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.active not in self.keys:
            raise KeyConfigError(f"{self.purpose} key ring: active key {self.active!r} "
                                 "is not in its keys")
        for kid in self.keys:
            if not _KID_RE.match(kid):
                raise KeyConfigError(f"{self.purpose} key id {kid!r}: use 1 to 64 of "
                                     "A-Z a-z 0-9 . _ -")

    @property
    def active_key(self) -> bytes:
        return self.keys[self.active]

    def get(self, kid: str) -> bytes | None:
        return self.keys.get(kid)

    def __repr__(self) -> str:  # never print key bytes
        return f"KeyRing({self.purpose!r}, active={self.active!r}, ids={sorted(self.keys)})"


@dataclass
class KeySet:
    fpe: KeyRing | None = None
    vault: KeyRing | None = None
    source: str = "env"

    def ring(self, purpose: str) -> KeyRing | None:
        return getattr(self, purpose)


# ---------------------------------------------------------------------------
# KMS unwrap / wrap
# ---------------------------------------------------------------------------

def _context(purpose: str) -> dict[str, str]:
    return {"taintward-key": purpose}


def _aws_client():
    try:
        import boto3
    except ImportError:
        raise KeyConfigError("aws-kms needs boto3: pip install 'taintward[aws]'") from None
    return boto3.client("kms")


def _gcp_client():
    try:
        from google.cloud import kms
    except ImportError:
        raise KeyConfigError("gcp-kms needs google-cloud-kms: pip install 'taintward[gcp]'") from None
    return kms.KeyManagementServiceClient()


# Tests swap these for fakes (GCP has no local emulator).
CLIENTS: dict[str, Callable[[], Any]] = {"aws": _aws_client, "gcp": _gcp_client}


def _vault_request(method: str, path: str, body: dict | None = None) -> dict:
    """Call the HashiCorp Vault HTTP API with VAULT_ADDR and VAULT_TOKEN."""
    addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
    token = os.environ.get("VAULT_TOKEN")
    if not token and os.environ.get("VAULT_TOKEN_FILE"):
        with open(os.environ["VAULT_TOKEN_FILE"]) as f:
            token = f.read().strip()
    if not addr or not token:
        raise KeyConfigError("HashiCorp Vault needs VAULT_ADDR and VAULT_TOKEN "
                             "(or VAULT_TOKEN_FILE)")
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    if os.environ.get("VAULT_NAMESPACE"):
        headers["X-Vault-Namespace"] = os.environ["VAULT_NAMESPACE"]
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{addr}/v1/{path.lstrip('/')}", data=data,
                                 headers=headers, method=method)
    ctx = None
    if os.environ.get("VAULT_CACERT"):
        import ssl
        ctx = ssl.create_default_context(cafile=os.environ["VAULT_CACERT"])
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raise KeyConfigError(f"HashiCorp Vault {method} {path}: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise KeyConfigError(f"HashiCorp Vault at {addr} not reachable: "
                             f"{getattr(exc, 'reason', exc)}") from None


def _split_kms(spec: str) -> tuple[str, str]:
    kind, sep, ref = spec.partition(":")
    if not sep or not ref or kind not in ("aws-kms", "gcp-kms", "vault-transit"):
        raise KeyConfigError(f"unknown kms {spec!r}; use aws-kms:<key>, "
                             "gcp-kms:projects/.../cryptoKeys/<key> or vault-transit:<key>")
    return kind, ref


def _transit_path(ref: str, op: str) -> str:
    mount, _, key = ref.rpartition("/")
    return f"{mount or 'transit'}/{op}/{key}"


def unwrap(spec: str, wrapped: str, purpose: str) -> bytes:
    """Turn a wrapped key back into key bytes with the named KMS."""
    kind, ref = _split_kms(spec)
    try:
        if kind == "aws-kms":
            out = CLIENTS["aws"]().decrypt(CiphertextBlob=base64.b64decode(wrapped),
                                           KeyId=ref, EncryptionContext=_context(purpose))
            key = out["Plaintext"]
        elif kind == "gcp-kms":
            out = CLIENTS["gcp"]().decrypt(request={
                "name": ref, "ciphertext": base64.b64decode(wrapped),
                "additional_authenticated_data": f"taintward-key={purpose}".encode()})
            key = out.plaintext
        else:
            out = _vault_request("POST", _transit_path(ref, "decrypt"), {"ciphertext": wrapped})
            key = base64.b64decode(out["data"]["plaintext"])
    except KeyConfigError:
        raise
    except Exception as exc:  # botocore / google api errors: keep only the type
        raise KeyConfigError(f"{kind} could not unwrap the {purpose} key: "
                             f"{type(exc).__name__}") from None
    if len(key) not in (16, 24, 32):
        raise KeyConfigError(f"{kind} returned a {purpose} key of {len(key)} bytes")
    return bytes(key)


def wrap(spec: str, key: bytes, purpose: str) -> str:
    """Wrap key bytes with the named KMS; the result goes in a key ring."""
    kind, ref = _split_kms(spec)
    try:
        if kind == "aws-kms":
            out = CLIENTS["aws"]().encrypt(KeyId=ref, Plaintext=key,
                                           EncryptionContext=_context(purpose))
            return base64.b64encode(out["CiphertextBlob"]).decode()
        if kind == "gcp-kms":
            out = CLIENTS["gcp"]().encrypt(request={
                "name": ref, "plaintext": key,
                "additional_authenticated_data": f"taintward-key={purpose}".encode()})
            return base64.b64encode(out.ciphertext).decode()
        out = _vault_request("POST", _transit_path(ref, "encrypt"),
                             {"plaintext": base64.b64encode(key).decode()})
        return out["data"]["ciphertext"]
    except KeyConfigError:
        raise
    except Exception as exc:
        raise KeyConfigError(f"{kind} could not wrap the {purpose} key: "
                             f"{type(exc).__name__}") from None


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def parse_ring_doc(doc: dict, source: str) -> KeySet:
    """Build a KeySet from key ring JSON, unwrapping wrapped keys."""
    if not isinstance(doc, dict):
        raise KeyConfigError(f"{source}: key ring must be a JSON object")
    default_kms = doc.get("kms")
    rings: dict[str, KeyRing] = {}
    for purpose in PURPOSES:
        sect = doc.get(purpose)
        if sect is None:
            continue
        if not isinstance(sect, dict) or not isinstance(sect.get("keys"), dict) or not sect["keys"]:
            raise KeyConfigError(f"{source}: {purpose} needs a non-empty 'keys' object")
        keys: dict[str, bytes] = {}
        for kid, entry in sect["keys"].items():
            what = f"{source}: {purpose} key {kid!r}"
            if isinstance(entry, str):
                entry = {"hex": entry}
            if not isinstance(entry, dict):
                raise KeyConfigError(f"{what} must be hex or an object")
            if "hex" in entry:
                keys[kid] = parse_hex_key(entry["hex"], what)
            elif "wrapped" in entry:
                kms = entry.get("kms") or default_kms
                if not kms:
                    raise KeyConfigError(f"{what} is wrapped but no 'kms' is set")
                keys[kid] = unwrap(kms, entry["wrapped"], purpose)
            else:
                raise KeyConfigError(f"{what} needs 'hex' or 'wrapped'")
        active = sect.get("active") or next(iter(sect["keys"]))
        rings[purpose] = KeyRing(purpose, active, keys)
    if rings.get("fpe") and rings.get("vault"):
        if set(rings["fpe"].keys.values()) & set(rings["vault"].keys.values()):
            raise KeyConfigError(f"{source}: a vault key must not also be an FPE key")
    return KeySet(fpe=rings.get("fpe"), vault=rings.get("vault"), source=source)


def _env_keyset() -> KeySet:
    ks = KeySet(source="env")
    fpe = os.environ.get("TAINTWARD_FPE_KEY")
    if fpe:
        key = parse_hex_key(fpe, "TAINTWARD_FPE_KEY")
        kid = os.environ.get("TAINTWARD_FPE_KEY_ID") or key_id_for(key)
        ks.fpe = KeyRing("fpe", kid, {kid: key})
    vk = os.environ.get("TAINTWARD_VAULT_KEY")
    if vk:
        key = parse_hex_key(vk, "TAINTWARD_VAULT_KEY")
        kid = os.environ.get("TAINTWARD_VAULT_KEY_ID") or key_id_for(key)
        keys = {kid: key}
        for n, old in enumerate(filter(None, os.environ.get(
                "TAINTWARD_VAULT_KEY_PREVIOUS", "").split(","))):
            ok = parse_hex_key(old, f"TAINTWARD_VAULT_KEY_PREVIOUS[{n}]")
            keys.setdefault(key_id_for(ok), ok)
        ks.vault = KeyRing("vault", kid, keys)
    return ks


def _read_source(spec: str) -> tuple[dict, str]:
    if spec.startswith("file:"):
        path = spec[len("file:"):]
        if path.startswith("//"):
            path = path[2:]
        try:
            with open(path) as f:
                return json.load(f), path
        except OSError as exc:
            raise KeyConfigError(f"cannot read key ring {path}: {exc.strerror}") from None
        except json.JSONDecodeError as exc:
            raise KeyConfigError(f"key ring {path} is not valid JSON (line {exc.lineno})") from None
    if spec.startswith("vault-kv:"):
        ref = spec[len("vault-kv:"):].strip("/")
        mount, _, path = ref.partition("/")
        if not path:
            raise KeyConfigError("vault-kv needs <mount>/<path>, e.g. vault-kv:secret/taintward")
        data = _vault_request("GET", f"{mount}/data/{path}")["data"]["data"]
        if isinstance(data.get("keyring"), str):
            data = json.loads(data["keyring"])
        return data, f"vault-kv:{ref}"
    raise KeyConfigError(f"unknown TAINTWARD_KEYS {spec.split(':')[0]!r}; use env, "
                         "file:<path> or vault-kv:<mount>/<path>")


def _merge_env(ks: KeySet) -> KeySet:
    """Env keys win for the active key; the ring's keys stay readable."""
    env = _env_keyset()
    for purpose in PURPOSES:
        e, r = env.ring(purpose), ks.ring(purpose)
        if e is None:
            continue
        if r is None:
            setattr(ks, purpose, e)
        else:
            setattr(ks, purpose, KeyRing(purpose, e.active, {**r.keys, **e.keys}))
    return ks


_CACHE: dict[str, KeySet] = {}
_CACHE_LOCK = threading.Lock()


def load_keys(spec: str | None = None) -> KeySet:
    """Load the key rings named by spec or TAINTWARD_KEYS.

    A ring from a file or Vault is loaded (and unwrapped) once per process
    and cached; call reload_keys() after rotating.
    """
    spec = (spec if spec is not None else os.environ.get("TAINTWARD_KEYS", "")).strip()
    if spec in ("", "env"):
        return _env_keyset()
    with _CACHE_LOCK:
        if spec not in _CACHE:
            doc, source = _read_source(spec)
            _CACHE[spec] = parse_ring_doc(doc, source)
        ks = _CACHE[spec]
    return _merge_env(KeySet(fpe=ks.fpe, vault=ks.vault, source=ks.source))


def reload_keys() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


# ---------------------------------------------------------------------------
# taintward-keys CLI
# ---------------------------------------------------------------------------

def _new_entry(kms: str | None, purpose: str) -> dict:
    key = os.urandom(32)
    if kms:
        return {"wrapped": wrap(kms, key, purpose), "kms": kms}
    return {"hex": key.hex()}


def _load_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _write_file(path: str, doc: dict) -> None:
    """Write atomically, readable by the owner only."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".keys-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _default_id(sect: dict) -> str:
    n = 1 + sum(1 for k in sect.get("keys", {}) if re.fullmatch(r"v\d+", k))
    while f"v{n}" in sect.get("keys", {}):
        n += 1
    return f"v{n}"


def cmd_rotate(args) -> int:
    doc = _load_file(args.file)
    sect = doc.setdefault(args.purpose, {"keys": {}})
    sect.setdefault("keys", {})
    kid = args.id or _default_id(sect)
    if not _KID_RE.match(kid):
        print(f"bad key id {kid!r}", file=sys.stderr)
        return 2
    if kid in sect["keys"]:
        print(f"{args.purpose} key {kid!r} already exists", file=sys.stderr)
        return 2
    if args.kms and not doc.get("kms"):
        doc["kms"] = args.kms  # later rotations wrap with it too
    sect["keys"][kid] = _new_entry(args.kms or doc.get("kms"), args.purpose)
    old = sect.get("active")
    sect["active"] = kid
    parse_ring_doc(doc, args.file)  # refuse to write a ring that does not load
    _write_file(args.file, doc)
    print(f"{args.purpose}: active key is now {kid}" + (f" (was {old})" if old else ""))
    if args.purpose == "vault" and old:
        print("run `taintward-keys reseal` to move vault rows to the new key, "
              f"then `taintward-keys retire --file {args.file} --purpose vault --id {old}`")
    return 0


def cmd_retire(args) -> int:
    doc = _load_file(args.file)
    sect = doc.get(args.purpose) or {}
    if args.id not in sect.get("keys", {}):
        print(f"no {args.purpose} key {args.id!r}", file=sys.stderr)
        return 2
    if sect.get("active") == args.id:
        print("cannot retire the active key; rotate first", file=sys.stderr)
        return 2
    del sect["keys"][args.id]
    _write_file(args.file, doc)
    print(f"{args.purpose}: retired {args.id}")
    return 0


def cmd_generate(args) -> int:
    print(json.dumps(_new_entry(args.kms, args.purpose)))
    return 0


def cmd_show(args) -> int:
    ks = load_keys(args.keys)
    print(f"source: {ks.source}")
    for purpose in PURPOSES:
        ring = ks.ring(purpose)
        if ring is None:
            print(f"{purpose}: not set")
            continue
        ids = ", ".join(k + (" (active)" if k == ring.active else "") for k in ring.keys)
        print(f"{purpose}: {ids}")
    return 0


def cmd_reseal(args) -> int:
    from taintward.sdk.vault import get_vault
    vault = get_vault(args.vault)
    if not hasattr(vault, "reseal"):
        print("this vault keeps nothing encrypted at rest; nothing to reseal")
        return 0
    n = vault.reseal()
    print(f"resealed {n} vault rows under the active vault key")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="taintward-keys",
                                description="Make, rotate and check Taintward key rings.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def ring_args(sp, need_id=False):
        sp.add_argument("--file", required=True, help="key ring JSON file")
        sp.add_argument("--purpose", choices=PURPOSES, required=True)
        sp.add_argument("--id", required=need_id, help="key id (default v1, v2, ...)")

    sp = sub.add_parser("rotate", help="add a new key and make it active")
    ring_args(sp)
    sp.add_argument("--kms", help="wrap the new key with this KMS (default: the ring's kms)")
    sp.set_defaults(fn=cmd_rotate)

    sp = sub.add_parser("retire", help="remove an old, inactive key")
    ring_args(sp, need_id=True)
    sp.set_defaults(fn=cmd_retire)

    sp = sub.add_parser("generate", help="print one new key entry as JSON")
    sp.add_argument("--purpose", choices=PURPOSES, required=True)
    sp.add_argument("--kms", help="wrap it with this KMS")
    sp.set_defaults(fn=cmd_generate)

    sp = sub.add_parser("show", help="list key ids per purpose (never key bytes)")
    sp.add_argument("--keys", help="key source (default $TAINTWARD_KEYS)")
    sp.set_defaults(fn=cmd_show)

    sp = sub.add_parser("reseal", help="re-encrypt vault rows under the active vault key")
    sp.add_argument("--vault", help="vault spec (default $TAINTWARD_VAULT)")
    sp.set_defaults(fn=cmd_reseal)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except KeyConfigError as exc:
        print(f"taintward-keys: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
