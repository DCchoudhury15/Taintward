"""Detected spans must not swallow the quotes around a value."""

import ast
import json

from taintward.sdk.detect import detect_text, mask_text
from taintward.sdk.redact import redact_payload


def test_mask_keeps_repr_quotes():
    text = "{'employee': 'Alice Lee', 'manager': 'Bob Perez', 'ssn': '234-12-1234'}"
    masked = mask_text(text, detect_text(text))
    parsed = ast.literal_eval(masked)
    assert "Alice" not in masked and "234-12-1234" not in masked
    assert parsed["employee"] == "[PII]"


def test_mask_keeps_json_quotes():
    text = json.dumps({"employee": "Alice Lee", "ssn": "234-12-1234"})
    assert json.loads(mask_text(text, detect_text(text)))["employee"] == "[PII]"


def test_masking_twice_does_not_nest_brackets():
    text = "{'employee': 'Alice Lee'}"
    once = redact_payload(text, "llm")
    assert redact_payload(once, "llm") == once
    assert "[[" not in once
