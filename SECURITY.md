# Security policy

Taintward is a security tool, so bugs in it can leak the data it is meant
to protect. Please report them privately.

## How to report

Report it privately on GitHub:
https://github.com/DCchoudhury15/Taintward/security/advisories/new

If that does not work for you, open a **confidential issue** on the GitLab
mirror instead:
https://gitlab.com/divyanshuchoudhury51/taintward/-/issues/new
(tick "This issue is confidential").

Please include:

- what you did, what you expected, and what happened
- the version (`pip show taintward`) and how you run it (SDK, MCP gateway, collector)
- a minimal example, with fake data only

You will get a reply within 5 days. Fixes for confirmed issues are released
as soon as they are ready, and you will be credited unless you ask not to be.

## What counts

Anything that lets a raw sensitive value reach a destination the policy says
it must not reach, for example:

- a detection bypass that also bypasses redaction (please include the input)
- a raw value stored in a span, a log line or the evidence log
- a way to reverse a one-way mask, or to read vault contents without the key
- a way to edit or delete evidence log records without the check failing
- the gateway forwarding a call that block mode should have stopped

Detection misses on new data formats are welcome too, but they are usually
not urgent. A normal issue with a fake example is fine for those.

## Known limits

These are documented and are not vulnerabilities on their own. The full
list, with the known bypasses and open gaps, is in `docs/threat-model.md`:

- detection is pattern and model based, so it can miss data
  (see `docs/benchmark.md` for measured accuracy)
- the FF1 code in `taintward/sdk/ff1.py` has not had an outside audit yet
- anyone holding the FPE key can reverse internal tokens
