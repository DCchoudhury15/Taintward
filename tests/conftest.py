"""Shared test setup.

A fixed FPE key, so tokens are the same on every run. Without it the
redactor makes a random key per process, and a few tests that depend on
the token's shape could fail for rare keys. Tests that check key handling
patch the environment themselves.
"""

import os

os.environ.setdefault("TAINTWARD_FPE_KEY", "EF4359D8D580AA4F7F036D6F04FB771B")
