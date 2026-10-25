# Redaction crypto: FF1, the token vault, and keys

This page explains how the reversible tokens for internal sinks are made,
where the token mapping is stored, and how to configure keys. It replaces the
old FF3 setup that Phase 4 first shipped with (see
[phase4-redaction.md](phase4-redaction.md)).

## What changed and why

| before | now | why |
|---|---|---|
| FF3 via the `ff3` package | FF1 in `sdk/ff1.py` (AES from `cryptography`) | NIST withdrew FF3 and FF3-1 (SP 800-38G Rev.1 draft, Feb 2025). FF1 is the FPE mode that is still approved. The `FPE` PyPI package did not build, so FF1 is implemented here (about 150 lines) and checked against all 9 official NIST FF1 sample vectors. |
| in-process dict vault | pluggable vault (`sdk/vault.py`): `MemoryVault`, `SQLiteVault`, `PostgresVault` or `RedisVault` | the dict was lost on restart and not shared between processes or hosts |
| hardcoded demo key used silently | no built-in key unless you opt in | a public key in the code makes every token reversible by anyone |

Token format is unchanged: same length, separators in the same place, digits
stay digits (an SSN `234-12-1234` becomes another `ddd-dd-dddd` string),
alnum values become lowercase alnum of the same length. Token values are
different from the FF3 ones, so tokens issued by an older build will not
reverse with this one.

## How a token is made

1. Take the letters and digits of the value, lowercase them. Separators stay put.
2. Pick the radix: 10 if all digits, else 36 (0-9a-z).
3. Encrypt with FF1. The tweak is built from a fixed label, an optional
   operator tweak, the radix and the value's shape (which positions were
   digits, lowercase or uppercase letters, and where the separators are).
   So `EMP4521XQ` and `emp4521xq` get different tokens instead of the same one.
4. Store `token -> original` in the vault, so reversal gives back the exact
   original, including letter case.

If a token already exists in the vault for a *different* original (possible
but rare for short values), the value is masked instead. An existing mapping
is never overwritten.

## Short values

FF1 needs a domain of at least 1,000,000 values (`radix ** length >= 1e6`).
That means at least **6 digits** or **4 letters/digits**. Shorter values
(`12345`, `Bob`) are **masked** (`[PII]` / `[SECRET]`) even for internal
sinks. Encrypting them would be weak (a tiny domain is easy to brute force)
and random tokens over a tiny domain collide often. Masking is the safe choice.

## The vault

Configure with `AGENTWARD_VAULT`:

| value | backend | notes |
|---|---|---|
| unset or `memory` | `MemoryVault` | default; lost on restart; one per process |
| `sqlite:///var/lib/agentward/vault.db` | `SQLiteVault` | persistent; one host; `sqlite://` + path, so three slashes means an absolute path |
| `postgresql://user:pass@host:5432/db` | `PostgresVault` | persistent; shared by many replicas on many hosts; needs `pip install "psycopg[binary]"` |
| `redis://host:6379/0` (`rediss://` for TLS) | `RedisVault` | shared by many replicas; native TTL; needs `pip install redis` |

### Which one to use

- **One process, demo or tests:** `memory`.
- **One host, a few processes:** `sqlite`. Nothing else to run.
- **Several replicas (Kubernetes, several hosts):** `postgresql`. It is the
  safest choice for data you must keep: it is durable, it has backups and
  point in time recovery, and erasure is a plain `DELETE`.
- **Several replicas with short lived tokens:** `redis`. Fast, and a TTL
  is a native Redis expiry, so expired tokens go away by themselves. Turn
  on persistence (`appendonly yes`), or a Redis restart loses every
  mapping. Use a single Redis (a primary with replicas or Sentinel is
  fine), not Redis Cluster.

### What every persistent backend guarantees

`SQLiteVault`, `PostgresVault` and `RedisVault` all work the same way:

- The original is stored **encrypted with AES-256-GCM** (random nonce per
  entry, token used as associated data so a ciphertext cannot be copied to
  another token). The plaintext never leaves the process: the database or
  Redis only ever sees ciphertext.
- They need `AGENTWARD_VAULT_KEY` (hex, 32/48/64 chars). They refuse to
  start without one, and refuse a key equal to `AGENTWARD_FPE_KEY`. Keep
  the two keys separate so losing one does not expose everything. Every
  replica must use the same vault key.
- The subject is stored only as an HMAC-SHA256 blind index (see erasure
  below).
- They support a TTL per entry (`Redactor(ttl=seconds)`), `delete(token)`
  and `forget_subject(subject)`. `purge_expired()` deletes expired rows in
  SQLite and Postgres (expired rows are already ignored on read); Redis
  does it by itself.

Backend details:

- `SQLiteVault`: safe for several processes on one host (WAL mode, busy
  timeout, short transactions). Do not put the file on NFS or other
  network storage.
- `PostgresVault`: one table (default `agentward_vault_tokens`, created on
  first start) with the token as primary key, the nonce, the ciphertext,
  the key id, the subject index and the expiry. There is an index on the
  subject index (for erasure) and a partial index on the expiry (for
  purging). A write is one `INSERT ... ON CONFLICT DO UPDATE`, so many
  writers at once never fail. Expiry uses the database clock, so replicas
  with different clocks agree. Connections come from a small pool
  (`pool_size=5`), with a 5 second connect timeout and a 5 second
  statement timeout; a dropped connection is replaced and the call is
  retried once.
- `RedisVault`: one hash per token (`agentward:vault:t:<token>`) holding
  the sealed value, the key id and the subject index, plus one set per
  subject index (`agentward:vault:s:<index>`) listing its tokens. Writes
  and erasure are Lua scripts, so each one is atomic. Connections come from
  redis-py's pool with a 5 second socket timeout.

If the database or Redis cannot be reached, the vault raises `VaultError`
with the host name in the message (never the password).

### Erasure (GDPR "forget me")

Pass a subject when redacting, then erase everything for that subject:

```python
r.redact_value(ssn, Sensitivity.PII, DEST_INTERNAL, subject="user-42")
r.forget_subject("user-42")   # deletes all vault rows for user-42
```

The subject is stored only as an HMAC-SHA256 blind index (keyed from the vault
key), so the file does not list subject ids in clear.

One catch: digit-only FF1 tokens can also be decrypted with just the FPE key,
without the vault. The Redactor does that as a fallback (`structural_fallback`)
only with `MemoryVault`, so tokens from another process can still be reversed.
With a persistent vault the fallback is off by default, so after
`forget_subject` the token can no longer be reversed through AgentWard. Anyone
who holds the FPE key can still decrypt digit-only tokens by hand. If you need
erasure to be cryptographically final, keep the FPE key in a place only the
redactor can use, or rotate it.

## Keys

| env | meaning |
|---|---|
| `AGENTWARD_FPE_KEY` | hex AES key for FF1, 32/48/64 hex chars (AES-128/192/256). Recommended: 64. |
| `AGENTWARD_FPE_KEY_ID` | optional label (e.g. `2026-10`) stored next to each token in the vault. Default: a short hash of the key. |
| `AGENTWARD_ALLOW_DEMO_KEY=1` | use the public demo key from the code. Demos only. |
| `AGENTWARD_VAULT_KEY` | hex AES-GCM key for the SQLite, Postgres and Redis vaults. Must differ from the FPE key. |

If `AGENTWARD_FPE_KEY` is unset and the demo key is not allowed, the Redactor
generates a **random key once per process** and logs a loud warning. Things
still work, but tokens change after a restart and differ between processes.
This is on purpose: nothing ever silently falls back to a known key.

Generate keys with:

```bash
python -c "import os; print(os.urandom(32).hex())"
```

**Rotation.** Set a new `AGENTWARD_FPE_KEY` (and a new `AGENTWARD_FPE_KEY_ID`).
New values get tokens under the new key. Old tokens still reverse through the
vault, because the vault stores the original, not something derived from the
key; the key id on each row tells you which key made it. The same value will
get a different token after rotation, so correlation across the rotation
point is lost. Rotating `AGENTWARD_VAULT_KEY` needs a re-encrypt of the file
and is not automated.

## Limits (be honest about these)

- FF1 is a **symmetric** scheme. Anyone with the FPE key can turn digit-only
  tokens back into values, and can check guesses for any token. Key storage,
  access control and rotation are on the operator. Use a secret manager, not
  a plain `.env` file, for anything real.
- Tokens are **deterministic**: the same value with the same key gives the
  same token. That is what makes correlation possible, but it also means
  equal tokens reveal equal values.
- Values with few possible values (short ids, small numbers) are guessable
  even above the 6 digit floor if the attacker can run the redactor.
- `sdk/ff1.py` matches the NIST vectors but has not had an external audit,
  and it is not constant time. Fine for this project; a regulated deployment
  should use a validated module (for example HashiCorp Vault Transform).
- `SQLiteVault` is single host. For several hosts use `PostgresVault` or
  `RedisVault`, or a managed tokenization service behind the same `Vault`
  protocol.
- The vault key is the same on every replica and is not rotated
  automatically. Anyone with the vault key and read access to the table
  or Redis can decrypt every stored original.

## Code

- `sdk/ff1.py`: FF1 (any radix 2..65536, AES-128/192/256, any tweak).
- `sdk/vault.py`: `Vault` protocol, `MemoryVault`, `SQLiteVault`,
  `PostgresVault`, `RedisVault`, `get_vault()`.
- `sdk/redact.py`: `Redactor` (uses both), `redact_value` / `redact_text` /
  `redact_payload` / `get_redactor` (same signatures as before, plus an
  optional `subject=` keyword).
- Tests: `tests/test_ff1.py` (NIST Samples 1 to 9, round trips, domain floor),
  `tests/test_vault.py` (persistence, encryption at rest, erasure, TTL,
  multi-process writers, key handling, short values),
  `tests/test_vault_backends.py` (the same checks against a real Postgres 18
  in docker and a real redis-server, including the raw table bytes on disk
  and the raw Redis values).
