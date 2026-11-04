"""Tests for the detection rules added for gap G9 (data outside US formats).

Covers the check digits and recognizers in taintward.sdk.recognizers_intl
(national ids, ids after an id word, international phone numbers, European
street addresses, inline passwords), how detect.py ranks overlapping hits,
the language guess that picks the name model, and the filters that drop
words the name model wrongly calls a name.

The sample ids are textbook examples or made up here with a valid check
digit; none belongs to a real person.
"""

from __future__ import annotations

import importlib.util

import pytest

from taintward.sdk import _lang, detect
from taintward.sdk import recognizers_intl as intl


def _analyzer_available() -> bool:
    try:
        detect._get_analyzer()
        return True
    except Exception:
        return False


needs_presidio = pytest.mark.skipif(not _analyzer_available(),
                                    reason="Presidio / spaCy model not installed")
needs_spacy = pytest.mark.skipif(importlib.util.find_spec("spacy") is None,
                                 reason="spaCy not installed")


def _hits(fn, text, key=""):
    return [(t, text[a:b]) for t, a, b, _ in fn(text, key)]


def _types(dets) -> set[str]:
    return {d.entity_type for d in dets if d.is_sensitive}


# ---------------------------------------------------------------------------
# Check digits
# ---------------------------------------------------------------------------

def test_check_digits_accept_valid_and_reject_one_changed_character():
    assert intl.aadhaar_ok("234567890124") and not intl.aadhaar_ok("234567890125")
    assert not intl.aadhaar_ok("134567890124")  # cannot start with 0 or 1
    assert intl.codice_fiscale_ok("RSSMRA85T10A562S")
    assert not intl.codice_fiscale_ok("RSSMRA85T10A562T")
    assert intl.dni_ok("12345678Z") and not intl.dni_ok("12345678A")
    assert intl.dni_ok("X1234567L") and not intl.dni_ok("X1234567M")
    assert intl.nir_ok("1 85 05 78 006 084 91") and not intl.nir_ok("185057800608492")
    assert not intl.nir_ok("185137800608425")  # right key, but month 13 does not exist
    assert intl.ahv_ok("756.1234.5678.97") and not intl.ahv_ok("756.1234.5678.98")
    assert intl.nino_ok("AB 12 34 56 C")
    assert not intl.nino_ok("QQ123456C")  # Q is never a first letter (HMRC example prefix)
    assert not intl.nino_ok("GB123456C")  # GB is not used
    assert not intl.nino_ok("AB123456E")  # last letter is A to D


# ---------------------------------------------------------------------------
# National ids found anywhere
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,etype,value", [
    ("Aadhaar copy: 2345 6789 0124 attached", "IN_AADHAAR", "2345 6789 0124"),
    ("cf RSSMRA85T10A562S in the form", "IT_FISCAL_CODE", "RSSMRA85T10A562S"),
    ("DNI 12345678Z", "ES_NIF", "12345678Z"),
    ("NIE X1234567L", "ES_NIE", "X1234567L"),
    ("n° 1 85 05 78 006 084 91 enregistré", "FR_NIR", "1 85 05 78 006 084 91"),
    ("AHV 756.1234.5678.97", "CH_AHV", "756.1234.5678.97"),
    ("NI AB 12 34 56 C on file", "UK_NINO", "AB 12 34 56 C"),
    ("PAN ABCPE1234F", "IN_PAN", "ABCPE1234F"),
])
def test_national_ids_are_found(text, etype, value):
    assert (etype, value) in _hits(intl.national_id, text)


@pytest.mark.parametrize("text", [
    "ref 2345 6789 0125",               # Aadhaar check digit wrong
    "code RSSMRA85T10A562T",            # codice fiscale check letter wrong
    "item 12345678A",                   # DNI letter wrong
    "batch 185057800608492",            # NIR key wrong
    "sku 756.1234.5678.98",             # AHV check digit wrong
    "example QQ123456C",                # not a valid NINO prefix
    "build 234567890124 finished",      # 12 digits, no Aadhaar word, no grouping
])
def test_national_ids_failing_their_rules_are_not_found(text):
    assert intl.national_id(text, "") == []


@pytest.mark.parametrize("text", [
    "card 4111 1111 1111 1111 on file",           # not the first 12 digits of a card
    "account GB29 NWBK 6016 1331 9268 19 ok",       # not a slice of a spaced IBAN
    "ref 2345 6789 0124 5678",
    "account 12 2345 6789 0124",                  # nor the end of a longer number
])
def test_grouped_ids_must_stand_alone(text):
    assert intl.national_id(text, "") == []


def test_plain_aadhaar_needs_the_word():
    assert ("IN_AADHAAR", "234567890124") in _hits(intl.national_id, "Aadhaar no 234567890124")
    assert ("IN_AADHAAR", "234567890124") in _hits(intl.national_id, "234567890124", "aadhaar")


# ---------------------------------------------------------------------------
# Any id after an id word
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,value", [
    ("Passnummer: I80376124", "I80376124"),
    ("Bien sûr, mon numéro de passeport est Z64989191.", "Z64989191"),
    ("Führerscheinnummer: 50-115657-09", "50-115657-09"),
    ("Numero di patente: P91-0567-426-67", "P91-0567-426-67"),
    ("Personnummer: 850730-5178", "850730-5178"),
    ("Steuer-ID 72216165850 bitte", "72216165850"),
    ("Driver's license number D1234567", "D1234567"),
])
def test_id_after_an_id_word(text, value):
    assert ("ID_NUMBER", value) in _hits(intl.keyed_id, text)


def test_id_under_an_id_key():
    assert _hits(intl.keyed_id, "X1234567", "passport_number") == [("ID_NUMBER", "X1234567")]
    assert _hits(intl.keyed_id, "AB 123 456", "tax_id") == [("ID_NUMBER", "AB 123 456")]


@pytest.mark.parametrize("text,key", [
    ("order id 12345678", ""),          # the plain word "id" is not enough
    ("A1234567", "id"),
    ("request_id: 98765432", ""),
    ("Passport expiry 2025-03-01", ""),  # a date, not an id
    ("Passnummer: siehe Anhang", ""),    # no id after the word
    ("Your order 12345678 ships today", ""),
    ("Passport photo attached.\nOrder 12345678 ships today", ""),  # id word on another line
    ("Passport photos are attached to this message, and the order 12345678 ships", ""),  # too far
])
def test_id_word_rule_leaves_other_numbers_alone(text, key):
    assert intl.keyed_id(text, key) == []


def test_us_ssn_shapes_are_left_to_the_ssn_rules():
    # An invalid US SSN under an SSN word stays unflagged (area 000), as
    # tests/test_detect_fast.py expects; other ids under "SSN" are found.
    assert intl.keyed_id("000228491", "ssn") == []
    assert intl.keyed_id("SSN: 000-22-8491", "") == []
    assert ("ID_NUMBER", "LNUBNT06R55H884T") in _hits(intl.keyed_id, "SSN: LNUBNT06R55H884T")


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,value", [
    ("Call +49 30 1234567 today", "+49 30 1234567"),
    ("whatsapp: +33 6 12 34 56 78", "+33 6 12 34 56 78"),
    ("+44-20-7946-0958 is the office", "+44-20-7946-0958"),
    ("Tel. 06 12 34 56 78", "06 12 34 56 78"),
    ("Handy: 0170 1234567", "0170 1234567"),
    ("per favore contattaci al 0502 18754143.", "0502 18754143"),
])
def test_phone_numbers(text, value):
    assert ("PHONE_NUMBER", value) in _hits(intl.intl_phone, text)


@pytest.mark.parametrize("text", [
    "phone 2024-03-02 10:30",           # a date after a phone word
    "+1 2 3",                           # too few digits
    "UTC+01:00",
    "version 0.12.345",
    "total 0123 4567 8910",             # no phone word, no + sign
    "x+1234567890",                     # part of an expression
    "Contact us any time. Our invoice total for this quarter was 0123 4567 8910",  # word too far
])
def test_phone_rule_leaves_other_numbers_alone(text):
    assert intl.intl_phone(text, "") == []


def test_local_phone_under_a_phone_key():
    assert _hits(intl.intl_phone, "030 1234567", "telefon") == [("PHONE_NUMBER", "030 1234567")]


# ---------------------------------------------------------------------------
# Street addresses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,value", [
    ("Adresse: Musterstraße 12, 10115 Berlin", "Musterstraße 12, 10115 Berlin"),
    ("12 rue de la Paix, 75002 Paris", "12 rue de la Paix, 75002 Paris"),
    ("Indirizzo: Via Roma 10", "Via Roma 10"),
    ("Calle Mayor 5, piso 2", "Calle Mayor 5, piso 2"),
    ("Kerkstraat 12a\n1012 AB Amsterdam", "Kerkstraat 12a\n1012 AB Amsterdam"),
    ("Storgatan 5\n114 55 Stockholm", "Storgatan 5\n114 55 Stockholm"),
    ("Meine Adresse ist 7 Hauensteinstrasse", "7 Hauensteinstrasse"),
    ("Chemin de Bellevue 2, 8953 Himmelried", "Chemin de Bellevue 2, 8953 Himmelried"),
])
def test_european_street_addresses(text, value):
    assert ("STREET_ADDRESS", value) in _hits(intl.intl_street_address, text)


@pytest.mark.parametrize("text", [
    "Ben   45   CA   Engineering   95000",  # "ring" is only a word ending
    "Police: 789-11-2017\n\nFraktförsäkring",  # parts on different lines
    "3. PLACE OF WORK\n4. JOB DESCRIPTION",
    "1.2 During the period",
    "Abfahrt von Bahnsteig 3",
    "Seit 2023 Verkäufer bei uns",
])
def test_street_rule_leaves_other_text_alone(text):
    assert intl.intl_street_address(text, "") == []


def test_us_street_suffixes_from_the_usps_list():
    from taintward.sdk.recognizers_extra import street_address

    assert ("STREET_ADDRESS", "710 Billy Junction") in _hits(street_address, "at 710 Billy Junction")
    # Everyday words are not street types: "2 Data Center" is not an address.
    assert street_address("in 2 Data Center", "") == []


# ---------------------------------------------------------------------------
# Passwords and keys written inline
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,value", [
    ("Passwort: Sommer2024!x (bitte ändern)", "Sommer2024!x"),
    ("Uw nieuwe wachtwoord is Kx9!rT2#mQ. Zorg ervoor", "Kx9!rT2#mQ"),
    ("confirm your API key: 7f3k9q2w8e7r6t5y |", "7f3k9q2w8e7r6t5y"),
    ("<ns:password>Zq8$wLp1</ns:password>", "Zq8$wLp1"),
])
def test_inline_passwords_and_keys(text, value):
    assert ("GENERIC_API_KEY", value) in _hits(intl.inline_secret, text)


@pytest.mark.parametrize("text", [
    "Password: Required",              # a word, not a password
    "Password: [password]",            # a template slot
    "Passwort: ********",
    "Reset your password: see the help page",
])
def test_inline_secret_rule_leaves_labels_alone(text):
    assert intl.inline_secret(text, "") == []


# ---------------------------------------------------------------------------
# How detect.py combines the hits
# ---------------------------------------------------------------------------

@needs_presidio
def test_id_word_wins_over_phone_guess_and_exact_ids_win_over_id_word():
    detect.clear_cache()
    assert _types(detect.detect_text("Personnummer: 850730-5178")) == {"ID_NUMBER"}
    assert _types(detect.detect_text("Codice fiscale: RSSMRA85T10A562S")) == {"IT_FISCAL_CODE"}


@needs_presidio
def test_id_word_gives_way_to_exact_types():
    detect.clear_cache()
    assert _types(detect.detect_text("national_id=536-22-8491")) == {"US_SSN"}
    assert _types(detect.detect_text('PAN = "4111111111111111"')) == {"CREDIT_CARD"}


@needs_presidio
def test_id_word_wins_over_a_phone_guess_on_the_same_characters():
    detect.clear_cache()
    text = "Contact: Passnummer 089 1234567"
    assert ("PHONE_NUMBER", "089 1234567") in _hits(intl.intl_phone, text)  # both rules fire
    assert _types(detect.detect_text(text)) == {"ID_NUMBER"}


@needs_presidio
def test_inline_key_rule_does_not_double_the_generic_key_hit():
    detect.clear_cache()
    dets = detect.detect_text("api_key=cleck8n6t4jwblo9lfce7g49m90itpgi")
    assert [d.entity_type for d in dets] == ["GENERIC_API_KEY"]


@needs_presidio
def test_uk_nhs_number_needs_its_context_word():
    detect.clear_cache()
    assert "UK_NHS" not in _types(detect.detect_text("call 943 476 5919 tomorrow"))
    assert "UK_NHS" in _types(detect.detect_text("NHS number 943 476 5919"))


@needs_presidio
def test_new_rules_run_through_detect_mapping():
    detect.clear_cache()
    found = _types(detect.detect_mapping({
        "passport_number": "X1234567", "phone": "+49 30 1234567",
        "address": "Musterstraße 12, 10115 Berlin", "note": "Passwort: Sommer2024!x"}))
    assert {"ID_NUMBER", "PHONE_NUMBER", "STREET_ADDRESS", "GENERIC_API_KEY"} <= found


@needs_presidio
def test_health_names_the_multilingual_model():
    assert "multilingual_model" in detect.health()


# ---------------------------------------------------------------------------
# Language guess and name model routing
# ---------------------------------------------------------------------------

def test_language_guess():
    assert _lang.guess("Please send the report to the team by Friday.") == "en"
    assert _lang.guess("Bitte schicken Sie mir die Unterlagen für den Antrag.") == "de"
    assert _lang.guess("Pouvez-vous me donner votre numéro de téléphone pour que nous") == "fr"
    assert _lang.guess("Anna Roth") is None
    # Pieces of a token are not words: "es", "la", "de", "el" inside a session id.
    assert _lang.guess("Cookie: session=x1es2la3de4el9los.c2lnbmVk") is None
    assert _lang.guess("Hello und goodbye") is None  # one stray word is not enough
    # Function words glued to digits or dots are pieces of a token.
    assert _lang.guess("token=Zm9vYmFy.les9des9et9la9le") is None


class _StubDoc:
    ents = ()


class _StubNlp:
    pipe_names = ["tok2vec", "ner"]

    def __init__(self):
        self.seen: list[str] = []

    def pipe(self, texts, disable=(), batch_size=32):
        for t in texts:
            self.seen.append(t)
            yield _StubDoc()


def test_text_in_another_language_goes_to_the_multilingual_model():
    eng = detect._Engine(recognizers=[])
    en, xx = _StubNlp(), _StubNlp()
    eng.nlp, eng.nlp_other = en, xx
    german = "Bitte schicken Sie die Unterlagen an Frau Weber."
    english = "Please send the files to Mrs Weber."
    alone = "Anna Weber"
    eng.run_ner([detect._Segment(t, "") for t in (german, english, alone)])
    assert any(german in s for s in xx.seen) and not any(german in s for s in en.seen)
    assert any(english in s for s in en.seen) and not any(english in s for s in xx.seen)
    assert any(alone in s for s in en.seen)  # no language signal: English model


def test_without_the_multilingual_model_everything_uses_the_english_one():
    eng = detect._Engine(recognizers=[])
    en = _StubNlp()
    eng.nlp, eng.nlp_other = en, None
    eng.run_ner([detect._Segment("Bitte schicken Sie die Unterlagen an Frau Weber.", "")])
    assert en.seen


def test_multilingual_model_can_be_turned_off_or_missing(monkeypatch):
    spacy = pytest.importorskip("spacy")
    loads = []
    monkeypatch.setattr(spacy, "load", lambda name, *a, **k: loads.append(name))
    monkeypatch.setenv("TAINTWARD_NER_MULTILINGUAL_MODEL", "off")
    assert detect._load_multilingual() is None
    assert loads == []  # "off" does not even try
    monkeypatch.undo()
    monkeypatch.setenv("TAINTWARD_NER_MULTILINGUAL_MODEL", "no_such_model_xyz")
    assert detect._load_multilingual() is None  # logged, not raised


# ---------------------------------------------------------------------------
# Filters for words the name model calls a name
# ---------------------------------------------------------------------------

def _filter(text: str, word: str):
    seg = detect._Segment(text, "")
    a = text.index(word)
    span = detect._name_filter(seg, a, a + len(word))
    return None if span is None else text[span[0]:span[1]]


@needs_spacy
def test_name_filter():
    assert _filter("Bitte melden Sie sich.", "Bitte") is None          # greeting word
    assert _filter("Hallo Anna, wie geht es?", "Hallo Anna") == "Anna"  # trimmed
    assert _filter("Bitte an [Empfängername] senden", "Empfängername") is None  # template slot
    assert _filter("Bitte an Empfängername senden", "Empfängername") == "Empfängername"
    assert _filter("Ihr Name (Anna Roth) fehlt.", "Anna Roth") == "Anna Roth"
    assert _filter("Policy\n\nThe policy covers fire.", "Policy") is None
    assert _filter("Balance Sheet\nthe balance sheet shows", "Balance Sheet") is None
    # Only when every word is a common word: "white" alone does not make it one.
    assert _filter("Rose White called. The white van left.", "Rose White") == "Rose White"
    assert _filter("Anna\nwrite to anna@example.com", "Anna") == "Anna"  # e-mail is not a word
    assert _filter("Meine Gedichte sind fertig.", "Meine Gedichte") is None
    assert _filter("Unsere Daten", "Unsere") is None                     # spaCy stop word
    assert _filter("Estoy listo.", "Estoy") is None
    assert _filter("Per Svensson ringde.", "Per") == "Per"               # a name, also a stop word
    assert _filter("Gracias, Lucía Fernández.", "Lucía Fernández") == "Lucía Fernández"
