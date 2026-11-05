"""A place name on its own is not personal data; next to other personal
data in the same value it is (TAINTWARD_LOCATION_ALONE turns the old rule
back on). These tests need the spaCy model, which finds the place names."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from taintward.sdk import detect
from taintward.sdk.redact import redact_payload

pytestmark = pytest.mark.skipif(
    detect.health()["mode"] != "full", reason="needs the spaCy model (place names come from NER)")

LONE = "I flew to Berlin last week."


def _types(text: str) -> set[str]:
    return {d.entity_type for d in detect.detect_text(text)}


@pytest.fixture
def alone():
    """Run a test with lone place names counting, then put the default back."""
    detect.set_location_alone(True)
    yield
    detect.set_location_alone(False)


def test_lone_place_name_is_not_sensitive():
    assert not detect.location_alone()
    assert detect.detect_text(LONE) == []
    assert not detect.taint_for(detect.detect_text(LONE)).is_tainted
    assert redact_payload(LONE, "llm") == LONE


@pytest.mark.parametrize("text, other", [
    ("Alice Smith lives in Berlin.", "PERSON"),
    ("Call me on +49 30 1234567, I am in Berlin.", "PHONE_NUMBER"),
    ("Write to alice@example.com, I moved to Berlin.", "EMAIL_ADDRESS"),
])
def test_place_name_next_to_personal_data_is_sensitive(text, other):
    assert _types(text) >= {"LOCATION", other}
    assert "Berlin" not in redact_payload(text, "llm")


def test_street_address_counts_on_its_own():
    assert "STREET_ADDRESS" in _types("Hauptstrasse 5, 10115 Berlin")


def test_old_rule_can_be_turned_back_on(alone):
    assert _types(LONE) == {"LOCATION"}
    assert "Berlin" not in redact_payload(LONE, "llm")


def test_switching_clears_cached_results():
    assert detect.detect_text(LONE) == []  # cached as nothing found
    detect.set_location_alone(True)
    try:
        assert _types(LONE) == {"LOCATION"}
    finally:
        detect.set_location_alone(False)
    assert detect.detect_text(LONE) == []


def test_env_variable_turns_the_old_rule_on():
    code = ("from taintward.sdk import detect;"
            f"print(sorted(d.entity_type for d in detect.detect_text({LONE!r})))")
    env = {**os.environ, "TAINTWARD_LOCATION_ALONE": "1"}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                         text=True, check=True).stdout.strip().splitlines()[-1]
    assert out == "['LOCATION']"
