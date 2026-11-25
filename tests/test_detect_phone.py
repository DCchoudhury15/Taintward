"""Phone numbers that needed a context word to be found.

"reach me at 212-736-5000" and "(212) 736-5000" were missed: the phone
matcher scores a bare number under the threshold, and "reach" was not one of
its context words. A number in a North American phone format is now found
on its own, and more words count as phone context."""

from __future__ import annotations

import pytest

from taintward.sdk.detect import detect_text


def _phones(text: str) -> list[str]:
    return [text[d.start:d.end] for d in detect_text(text) if d.entity_type == "PHONE_NUMBER"]


@pytest.mark.parametrize("text, want", [
    ("reach me at 212-736-5000", "212-736-5000"),
    ("(212) 736-5000 anytime", "(212) 736-5000"),
    ("212.736.5000", "212.736.5000"),
    ("1-212-736-5000", "1-212-736-5000"),
    ("order 212-736-5000 shipped", "212-736-5000"),
    ("dial 0151 23456789", "0151 23456789"),
    ("reach me on 030 1234567", "030 1234567"),
])
def test_phone_without_the_old_context_words(text, want):
    assert _phones(text) == [want]


@pytest.mark.parametrize("text", [
    "212-736.5000",            # mixed separators
    "112-736-5000",            # an area code cannot start with 0 or 1
    "ver 212.736.5000.1",      # part of a longer dotted number
    "x/212-736-5000",          # part of a path
    "id 2024-01-1234",
    "between 2019-2020 and 3-5 items",
    "ssn 234-12-1234",
])
def test_numbers_that_are_not_phones(text):
    assert _phones(text) == []
