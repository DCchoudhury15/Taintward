# Key management and rotation

Taintward uses two secret keys:

| purpose | what it does | where it is used |
|---|---|---|
| `fpe` | AES key for FF1; makes the reversible tokens for internal sinks | `Redactor` |
| `vault` | AES-GCM key; seals each original in the vault | `SQLiteVault`, `PostgresVault`, `RedisVault` |

Each purpose has a **key ring**: one active key that is used for new work,
plus older keys that are only used to read what they made. This page shows
where rings can come from, how to keep keys wrapped by a KMS, and how to
rotate. How the keys are used is in [Redaction crypto](redaction-crypto.md).

## Where keys come from

Set `TAINTWARD_KEYS`:

| value | source |
|---|---|
| unset or `env` | `TAINTWARD_FPE_KEY` and `TAINTWARD_VAULT_KEY`, one key each (the old setup, unchanged) |
| `file:/etc/taintward/keys.json` | a key ring file |
| `vault-kv:secret/taintward` | the same ring stored in HashiCorp Vault KV v2 (`<mount>/<path>`) |

`TAINTWARD_FPE_KEY` and `TAINTWARD_VAULT_KEY` still win when they are set:
they become the active key, and the ring's keys stay readable. So you can
move to a ring without changing anything else first.

HashiCorp Vault is called over its HTTP API with the standard settings:
`VAULT_ADDR`, `VAULT_TOKEN` (or `VAULT_TOKEN_FILE`), and optionally
`VAULT_NAMESPACE` and `VAULT_CACERT`. No extra Python package is needed.
In KV, store the ring as the secret's data, or as a JSON string under the
field `keyring`.

A ring from a file or Vault is read once per process and cached. Restart
the process (or call `taintward.sdk.keys.reload_keys()`) after a rotation.

## The key ring file

```json
{
  "kms": "aws-kms:alias/taintward",
  "fpe": {
    "active": "v2",
    "keys": {
      "v1": {"wrapped": "AQICAHh...", "kms": "aws-kms:alias/taintward"},
      "v2": {"wrapped": "AQICAHi..."}
    }
  },
  "vault": {
    "active": "v1",
    "keys": {"v1": {"wrapped": "AQICAHj..."}}
  }
}
```

- `active` names the key for new work. If it is missing, the first key is
  active.
- A key is either plain hex (`"v1": "<hex>"` or `{"hex": "<hex>"}`), or
  **wrapped** by a KMS (`{"wrapped": ...}`). A wrapped key uses its own
  `kms`, or the ring's top level `kms`.
- Key ids are 1 to 64 of `A-Z a-z 0-9 . _ -`. The FPE key id is stored next
  to each token in the vault, and the vault key id is stored in each sealed
  row.
- A key may not be in both the `fpe` and the `vault` ring.

`taintward-keys` writes this file for you (below), with mode `0600`.

## Wrapped keys (envelope encryption)

With a wrapped key, the ring file holds only ciphertext. The KMS unwraps it
once, when the ring is loaded, and the key then lives in process memory.
Someone who copies the file gets nothing without KMS access.

| `kms` value | service | needs |
|---|---|---|
| `aws-kms:<key id, ARN or alias/...>` | AWS KMS `Decrypt` | `pip install "taintward[aws]"`, the normal AWS credentials and region (`AWS_ENDPOINT_URL` works too) |
| `gcp-kms:projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>` | Google Cloud KMS | `pip install "taintward[gcp]"`, application default credentials |
| `vault-transit:[<mount>/]<key>` | HashiCorp Vault Transit (mount `transit` by default) | `VAULT_ADDR`, `VAULT_TOKEN` |

AWS and GCP wraps are bound to their purpose (encryption context or
additional data `taintward-key=fpe` or `vault`). A wrapped vault key put in
the `fpe` ring fails to unwrap.

Give the Taintward process permission to **decrypt** only. Wrapping happens
when you rotate, from a machine or pipeline that may **encrypt**.

## Rotation

### Make a ring

```bash
taintward-keys rotate --file keys.json --purpose fpe   --kms aws-kms:alias/taintward
taintward-keys rotate --file keys.json --purpose vault
taintward-keys show --keys file:keys.json
```

The first `--kms` is saved as the ring's default, so later rotations are
wrapped the same way. `show` lists key ids only, never key bytes:

```
source: keys.json
fpe: v1 (active)
vault: v1 (active)
```

Put the file in your secret store, or write the same JSON to Vault KV, and
point `TAINTWARD_KEYS` at it.

### Rotate the vault key

```bash
taintward-keys rotate --file keys.json --purpose vault        # v2 is active, v1 kept
# deploy the new ring to every replica, then:
TAINTWARD_KEYS=file:keys.json taintward-keys reseal --vault postgresql://...
taintward-keys retire --file keys.json --purpose vault --id v1
```

1. **rotate** adds a new key and makes it active. Old rows still open:
   each row names the key that sealed it.
2. **Deploy** the new ring everywhere. New rows are sealed with the new key.
3. **reseal** goes through the vault and seals every row that is not on
   the active key again, including its subject index for erasure. It works
   on SQLite, Postgres and Redis, keeps TTLs, and only replaces a row that
   did not change while it ran. Running it again does nothing.
4. **retire** removes the old key once nothing needs it. It refuses to
   remove the active key.

While old and new keys are both in the ring, `forget_subject` finds rows
indexed under either key, so erasure works during the whole rotation.

With the `env` provider, the same steps are: set the new key in
`TAINTWARD_VAULT_KEY`, the old one in `TAINTWARD_VAULT_KEY_PREVIOUS`
(comma separated for more than one), run `reseal`, then drop the old one.

### Rotate the FPE key

```bash
taintward-keys rotate --file keys.json --purpose fpe
```

New values get tokens under the new key. Old tokens still reverse through
the vault, which keeps the original, not something derived from the key.
Two things to know:

- **The same value gets a different token after the rotation**, so
  joining internal data across the rotation point does not work. Rotate
  the FPE key on a schedule you can plan around, or when a key may have
  leaked.
- The digit-only fallback (`structural_fallback`, on only with
  `MemoryVault`) uses the active key, so it cannot reverse tokens made
  under an older key. Persistent vaults do not use it.

Keep old FPE keys in the ring as long as you want to be able to check who
made a token. Retiring one makes erasure of its digit-only tokens final:
no one can decrypt them without the vault any more.

### Rows from before key rings

Vault rows written by an earlier version have no key id. They are opened by
trying each key in the ring (the AES-GCM tag tells which key is right), and
`reseal` moves them to the active key. Their subject index is kept as it
was, because those rows do not hold the subject, so keep the key that wrote
them in the ring if you still need to erase them by subject.

## Errors

A ring that does not load stops the process with a `KeyConfigError` that
says what is wrong (missing active key, bad hex, wrong length, wrapped key
with no `kms`, KMS unreachable, KMS refused). Messages never contain key
bytes, and KMS errors show only the error type.

A vault row sealed with a key that is no longer in the ring raises
`VaultError` naming the missing key id.

## Code

- `taintward/sdk/keys.py`: rings, providers, KMS wrap and unwrap, the
  `taintward-keys` command.
- `taintward/sdk/vault.py`: `_Sealer` (key id in each row, open with any
  key in the ring, erasure under every key, `reseal`).
- `taintward/sdk/redact.py`: the Redactor takes its FPE key from the ring.
- Tests: `tests/test_keys.py` (rings, rotation, reseal, erasure across
  rotation, old rows, CLI, wrapped keys with a fake GCP client),
  `tests/test_keys_services.py` (HashiCorp Vault KV and Transit, AWS KMS on
  LocalStack, in docker), `tests/test_vault_backends.py::test_vault_key_rotation_reseal`
  (Postgres and Redis).
