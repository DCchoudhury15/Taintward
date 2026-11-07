"""Taintward control plane: one service for many tenants.

* each tenant's tool policy (the SDK destination map), versioned, pulled by
  the SDK (``taintward.sdk.control``),
* span upload (OTLP/HTTP) into each tenant's own span store and evidence
  log, with raw values masked before anything is stored,
* each tenant's report, compliance mapping, offline audit and evidence
  proofs.

The tenant always comes from the API token, never from the uploaded data.
See docs/control-plane.md.
"""
