"""Recognizers for data outside the US formats (gap G9).

All are plain-Python context recognizers with the same signature as the ones
in ``recognizers_extra``: ``fn(text, key_words) -> [(entity_type, start, end,
score)]``. Each one starts with a cheap test so most values cost almost
nothing.

* **National ids with a check digit** are found anywhere, because the check
  digit keeps false alarms rare: Indian Aadhaar (Verhoeff), Italian codice
  fiscale, Spanish DNI / NIE, French NIR, Swiss AHV, UK National Insurance
  numbers (letter rules), Indian PAN (fixed letter layout). A value that
  fails its check is not flagged, the same rule as for cards and IBANs.
* **Any id next to an id word** ("Passnummer:", "numéro de passeport",
  "Codice fiscale", "driver's license", ...) in English, German, French,
  Spanish, Italian, Dutch and Swedish, or under such a JSON key
  (``passport_number``, ``tax_id``). The plain word "id" is not enough:
  order, user and request ids are everywhere in tool data.
* **Phone numbers** written with a ``+`` country code, or after a phone
  word in one of those languages ("Tel.", "Handy", "portable", "móvil").
* **Street addresses** in the usual European forms ("Musterstraße 12",
  "12 rue de la Paix", "Via Roma 10", "Calle Mayor 5", "Kerkstraat 12",
  "Storgatan 5"), joined with a postal code and city right after them.
* **Passwords and API keys written inline** ("Passwort: ...", "wachtwoord
  is ...", "API key: ...", ``<password>...</password>``). The value must
  have a digit or a symbol, so "Password: Required" is left alone.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Check digits
# ---------------------------------------------------------------------------

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def aadhaar_ok(digits: str) -> bool:
    """12 digits, not starting with 0 or 1, Verhoeff check digit."""
    return (len(digits) == 12 and digits[0] not in "01" and digits != digits[::-1]
            and verhoeff_ok(digits))


_CF_ODD = dict(zip("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                   (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
                    2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23)))


def codice_fiscale_ok(code: str) -> bool:
    """Italian fiscal code: 15 characters plus a check letter."""
    code = code.upper()
    # ASCII letters and digits only: the pattern's \d also matches digits of
    # other scripts, which are not in the table (and are not a fiscal code).
    if len(code) != 16 or any(ch not in _CF_ODD for ch in code):
        return False
    total = 0
    for i, ch in enumerate(code[:15]):
        if i % 2 == 0:  # 1st, 3rd, ... (odd positions, counting from 1)
            total += _CF_ODD[ch]
        else:
            total += int(ch) if ch.isdigit() else ord(ch) - 65
    return chr(65 + total % 26) == code[15]


_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def dni_ok(code: str) -> bool:
    """Spanish DNI (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter)."""
    code = code.upper().replace("-", "").replace(" ", "")
    if len(code) != 9:
        return False
    head = code[:8]
    if head[0] in "XYZ":
        head = str("XYZ".index(head[0])) + head[1:]
    if not head.isdigit():
        return False
    return _DNI_LETTERS[int(head) % 23] == code[8]


def nir_ok(code: str) -> bool:
    """French social security number (NIR): 13 characters + 2-digit key."""
    code = re.sub(r"[\s.-]", "", code).upper()
    if len(code) != 15 or code[0] not in "12":
        return False
    body, key = code[:13], code[13:]
    body = body.replace("2A", "19").replace("2B", "18")
    if not body.isdigit() or not key.isdigit():
        return False
    month = int(code[3:5])
    if not (1 <= month <= 12 or 20 <= month <= 42 or 50 <= month <= 99):
        return False
    return 97 - int(body) % 97 == int(key)


def ahv_ok(code: str) -> bool:
    """Swiss social security number: 756 + 9 digits + EAN-13 check digit."""
    digits = re.sub(r"\D", "", code)
    if len(digits) != 13 or not digits.startswith("756"):
        return False
    total = sum(int(d) * (3 if i % 2 else 1) for i, d in enumerate(digits[:12]))
    return (10 - total % 10) % 10 == int(digits[12])


_NINO_BAD_PREFIX = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


def nino_ok(code: str) -> bool:
    """UK National Insurance number letter rules."""
    code = code.replace(" ", "").upper()
    if len(code) != 9:
        return False
    p = code[:2]
    return (p not in _NINO_BAD_PREFIX and p[0] not in "DFIQUV" and p[1] not in "DFIOQUV"
            and code[2:8].isdigit() and code[8] in "ABCD")


# ---------------------------------------------------------------------------
# National ids found anywhere (check digit or strict layout)
# ---------------------------------------------------------------------------

# Grouped numbers must stand alone: not the first 12 digits of a spaced card
# number ("4111 1111 1111 1111") or a slice of a spaced IBAN.
_ALONE_BEFORE = r"(?<![\w-])(?<!\d[ -])"
_ALONE_AFTER = r"(?![\w-])(?![ -]\d)"
_AADHAAR = re.compile(_ALONE_BEFORE + r"[2-9]\d{3}([ -])\d{4}\1\d{4}" + _ALONE_AFTER)
_AADHAAR_PLAIN = re.compile(r"(?<![\w-])[2-9]\d{11}(?![\w-])")
_CF = re.compile(r"(?<![\w-])[A-Z]{6}[\dLMNPQRSTUV]{2}[ABCDEHLMPRST][\dLMNPQRSTUV]{2}"
                 r"[A-Z][\dLMNPQRSTUV]{3}[A-Z](?![\w-])", re.IGNORECASE)
_DNI = re.compile(r"(?<![\w-])(?:\d{8}|[XYZ]\d{7})-?[A-Z](?![\w-])")
_NIR = re.compile(_ALONE_BEFORE + r"[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}"
                  + _ALONE_AFTER)
_AHV = re.compile(_ALONE_BEFORE + r"756[. ]?\d{4}[. ]?\d{4}[. ]?\d{2}" + _ALONE_AFTER)
_NINO = re.compile(_ALONE_BEFORE + r"[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]" + _ALONE_AFTER)
_PAN = re.compile(r"(?<![\w-])[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z](?![\w-])")
_AADHAAR_WORD = re.compile(r"(?i)aadhaa?r|\buid\b|आधार")

_DIGIT_HINT = re.compile(r"\d{2}")


def national_id(text: str, key_words: str) -> list[tuple]:
    if not _DIGIT_HINT.search(text):
        return []
    out = []
    for m in _AADHAAR.finditer(text):
        if aadhaar_ok(re.sub(r"\D", "", m.group(0))):
            out.append(("IN_AADHAAR", m.start(), m.end(), 0.6))
    if _AADHAAR_WORD.search(key_words or "") or _AADHAAR_WORD.search(text):
        for m in _AADHAAR_PLAIN.finditer(text):
            if aadhaar_ok(m.group(0)) and (
                    _AADHAAR_WORD.search(key_words or "")
                    or _AADHAAR_WORD.search(text, max(0, m.start() - 48), m.start())):
                out.append(("IN_AADHAAR", m.start(), m.end(), 0.6))
    for m in _CF.finditer(text):
        if codice_fiscale_ok(_cf_digits(m.group(0))) or codice_fiscale_ok(m.group(0)):
            out.append(("IT_FISCAL_CODE", m.start(), m.end(), 0.6))
    for m in _DNI.finditer(text):
        if dni_ok(m.group(0)):
            etype = "ES_NIE" if m.group(0)[0] in "XYZ" else "ES_NIF"
            out.append((etype, m.start(), m.end(), 0.6))
    for m in _NIR.finditer(text):
        if nir_ok(m.group(0)):
            out.append(("FR_NIR", m.start(), m.end(), 0.6))
    for m in _AHV.finditer(text):
        if ahv_ok(m.group(0)):
            out.append(("CH_AHV", m.start(), m.end(), 0.6))
    for m in _NINO.finditer(text):
        if nino_ok(m.group(0)):
            out.append(("UK_NINO", m.start(), m.end(), 0.6))
    for m in _PAN.finditer(text):
        out.append(("IN_PAN", m.start(), m.end(), 0.6))
    return out


# Omocodia: in a codice fiscale shared by two people, digits are swapped for
# these letters. The check letter is computed on the code as written, so this
# is only used to read the date; kept for completeness.
def _cf_digits(code: str) -> str:
    return code


# ---------------------------------------------------------------------------
# Any id next to an id word
# ---------------------------------------------------------------------------

_ID_WORDS = (
    # passports
    r"passport|passeport|pasaporte|passaporto|paspoort|reisepass|passnummer|passnr|pass-nr"
    # driving licences
    r"|driv\w*[\s'’-]*licen[cs]e|licen[cs]e\s*(?:number|no|nr|#)|führerschein|fahrerlaubnis"
    r"|permis\s+de\s+conduire|licencia\s+de\s+conducir|carn[eé]t?\s+de\s+conducir"
    r"|patente\s+di\s+guida|numero\s+di\s+patente|rijbewijs|körkort"
    # identity cards and generic national ids
    r"|id[\s_-]*(?:card|number|no\b|nr\b|nummer|numero|número|numéro|kort)|identity\s*card"
    r"|national[\s_-]*id|personalausweis|ausweisnummer|carte\s+d['’]identit|documento\s+de\s+identidad"
    r"|carta\s+d['’]identit|identiteitskaart|identitetskort|legitimation"
    # social security, tax and citizen numbers
    r"|social[\s_-]*security|sécurité\s+sociale|securite\s+sociale|seguridad\s+social"
    r"|previdenza\s+sociale|sozialversicherung|personnummer|personnr|samordningsnummer"
    r"|burgerservicenummer|sofinummer|codice\s+fiscale|codice_fiscale|tax[\s_-]*(?:id|number|no\b)"
    r"|steuer[\s-]*id|steuernummer|steueridentifikationsnummer|identifiant\s+fiscal"
    r"|num[ée]ro\s+fiscal|n[uú]mero\s+fiscal|national\s+insurance|aadhaa?r"
)
_ID_WORD = re.compile(r"(?i)(?:" + _ID_WORDS + r")")
# Short acronyms only count in capitals ("DNI", not "dni" inside a word).
_ID_ACRONYM = re.compile(r"(?<![A-Za-z])(?:SSN|DNI|NIE|NIF|CNI|BSN|NIR|PAN|AHV|AVS|NINO|TIN|"
                         r"CPF|PESEL|CURP|RUT|NHS)(?![A-Za-z])")
# An id: letters and digits, maybe split by spaces, dots, dashes or slashes,
# with at least four digits. Upper case only, so words are not picked up.
_ID_VALUE = re.compile(
    r"(?<![\w./-])(?=[A-Z0-9./ -]*\d[A-Z0-9./ -]*\d[A-Z0-9./ -]*\d[A-Z0-9./ -]*\d)"
    r"[A-Z0-9]{1,20}(?:[ ./-][A-Z0-9]{1,12}){0,5}(?![\w-]|[./][A-Z0-9])")
# A value that starts with a date ("2024-03-02 10:30", "02.03.2024 10").
_STARTS_DATE = re.compile(r"(?:\d{4}[./-]\d{1,2}[./-]\d{1,2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})(?!\d)")
_ID_WINDOW = 40


# A US social security number is left to the SSN recognizers, which know
# its rules (no area 000, 666 or 9xx, ...), so an invalid one stays unflagged.
_US_SSN_WORD = re.compile(r"(?i)ssn|social[\s_-]*security")
_US_SSN_SHAPE = re.compile(r"\d{3}-?\d{2}-?\d{4}")


def _id_words(text: str, start: int) -> list[str]:
    """The id words in the same line, at most _ID_WINDOW characters before."""
    lo = max(0, start - _ID_WINDOW)
    nl = text.rfind("\n", lo, start)
    lo = nl + 1 if nl >= 0 else lo
    return ([m.group(0) for m in _ID_WORD.finditer(text, lo, start)]
            + [m.group(0) for m in _ID_ACRONYM.finditer(text, lo, start)])


def _key_id_words(key_words: str) -> list[str]:
    if not key_words:
        return []
    return ([m.group(0) for m in _ID_WORD.finditer(key_words.replace("_", " "))]
            + [m.group(0) for m in _ID_ACRONYM.finditer(key_words.upper())])


def keyed_id(text: str, key_words: str) -> list[tuple]:
    """An id-shaped value right after an id word, or under an id key."""
    key_words_found = _key_id_words(key_words)
    if not key_words_found and not (_ID_WORD.search(text) or _ID_ACRONYM.search(text)):
        return []
    out = []
    for m in _ID_VALUE.finditer(text):
        value = m.group(0).strip()
        if len(re.sub(r"[^A-Z0-9]", "", value)) < 5 or _STARTS_DATE.match(value):
            continue
        if key_words_found and len(value) >= len(text.strip()) - 2:
            words = key_words_found
        else:
            words = _id_words(text, m.start())
        if not words:
            continue
        if _US_SSN_SHAPE.fullmatch(value) and all(_US_SSN_WORD.fullmatch(w) for w in words):
            continue
        out.append(("ID_NUMBER", m.start(), m.start() + len(value), 0.6))
    return out


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

_INTL_PHONE = re.compile(r"(?<![\w+])\+\d{1,3}(?:[ .\-/]?\(?\d{1,5}\)?){1,7}(?!\w)")
_PHONE_WORD = re.compile(
    r"(?i)(?:phone|telephone|tel\b|tel\.|mobile|cell|fax|whatsapp|sms|contact|call\b|calling"
    r"|telefon|rufnummer|handy|mobil|anrufen|rufen|téléphone|tél\b|tél\.|portable|appeler"
    r"|contacter|teléfono|telefono|móvil|celular|llamar|contactar|cellulare|chiamare|chiamaci"
    r"|contattare|contattaci|telefoon|mobiel|gsm|bellen|mobilnummer|mobiltelefon|ringa|ring\b)")
# A local number: starts with 0, or is written in groups ("(797) 230 2377").
_LOCAL_PHONE = re.compile(
    r"(?<![\w+.,/-])(?:\(?0\d{1,4}\)?(?:[ .\-/]?\d{2,6}){1,5}"
    r"|\(?[1-9]\d{1,3}\)?(?:[ .\-/]\d{2,6}){2,5})(?![\w-]|[.,]\d)")
_PHONE_WINDOW = 40


def _phone_possible(number: str) -> bool:
    try:
        import phonenumbers
    except ImportError:  # pragma: no cover - presidio depends on it
        return 8 <= len(re.sub(r"\D", "", number)) <= 15
    try:
        num = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException:
        return False
    return phonenumbers.is_possible_number(num)


def intl_phone(text: str, key_words: str) -> list[tuple]:
    """+CC numbers (any country), and local numbers after a phone word or
    under a phone key.

    A ``+`` followed by 9 to 15 digits in phone-style groups is taken as a
    phone number even when the number plan says it cannot exist: nothing
    else in tool data is written that way, and a made-up or mistyped number
    is still someone's contact detail."""
    out = []
    if "+" in text:
        for m in _INTL_PHONE.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 9 <= len(digits) <= 15 or (len(digits) == 8 and _phone_possible(m.group(0))):
                out.append(("PHONE_NUMBER", m.start(), m.end(), 0.6))
    key_hit = bool(key_words) and bool(_PHONE_WORD.search(key_words))
    if key_hit or _PHONE_WORD.search(text):
        for m in _LOCAL_PHONE.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if not 8 <= len(digits) <= 13 or _STARTS_DATE.match(m.group(0).lstrip("(")):
                continue
            if key_hit or _PHONE_WORD.search(text, max(0, m.start() - _PHONE_WINDOW), m.start()):
                out.append(("PHONE_NUMBER", m.start(), m.end(), 0.6))
    return out


# ---------------------------------------------------------------------------
# Street addresses
# ---------------------------------------------------------------------------

_CAP = r"[A-ZÀ-ÖØ-Þ][\wÀ-ÖØ-öø-ÿ'’.-]*"
_LOW = r"[\wÀ-ÖØ-öø-ÿ'’.-]+"
_HOUSE = r"\d{1,5}(?:[ \t]?[a-zA-Z](?![\w]))?(?:[ \t]?(?:bis|ter))?"
# Words of one address stay on one line; only the postal code and city may
# follow on the next line.
_SP = r"[ \t]{1,2}"
# German, Dutch and Swedish: the street type is the end of the word. Endings
# that are also common word endings ("ring": Engineering, "ufer": Verkäufer)
# are left out.
_GLUED = (r"(?:straße|strasse|str\.|weg|platz|gasse|allee|damm|chaussee"
          r"|straat|laan|plein|gracht|kade|singel|dijk|steeg"
          r"|gatan|vägen|gränd|torget|backe|stigen|platsen|allén)")
# Street words that come before the name (French, Italian, Spanish,
# Portuguese), in either case: "rue", "Via", "calle".
_PREFIX = (r"(?i:rue|avenue|av\.|boulevard|bd|place|chemin|allée|impasse|quai|route|cours|via|viale"
           r"|piazza|piazzale|corso|largo|vicolo|strada|calle|c/|avenida|avda\.|plaza|paseo|camino"
           r"|carrera|ronda|travesía|rambla|carretera|urbanización|rua|praça)")
_PARTICLES = r"(?:(?:de|du|des|la|le|les|l['’]|del|della|di|dei|degli|las|los|el)[ \t]*){0,3}"
_EN_SUFFIX = r"(?:Street|Avenue|Road|Lane|Drive|Boulevard|Way|Court|Place)"
_STREET_FORMS = (
    # Musterstraße 12, Lange Straße 5, Kerkstraat 12a, Storgatan 5, Towner Avenue 15
    rf"{_CAP}{_GLUED}{_SP}{_HOUSE}",
    rf"(?:{_CAP}{_SP}){{1,3}}(?:Straße|Strasse|Str\.|Weg|Platz|Gasse|Allee|{_EN_SUFFIX})"
    rf"{_SP}{_HOUSE}",
    # 7 Hauensteinstrasse, 73 Morrisbaan (number first, also seen in Europe)
    rf"{_HOUSE}{_SP}{_CAP}{_GLUED}",
    # 12 rue de la Paix, 4 bis avenue Foch, 61 Via Nicolò
    rf"{_HOUSE},?{_SP}{_PREFIX}{_SP}{_PARTICLES}{_CAP}(?:{_SP}{_CAP}){{0,3}}",
    # Via Roma 10, Piazza San Marco 1, Calle Mayor 5, Chemin de Bellevue 2
    rf"{_PREFIX}{_SP}{_PARTICLES}{_CAP}(?:(?:{_SP}|-){_CAP}){{0,3}},?{_SP}(?:n[º°.]?[ \t]*)?{_HOUSE}",
)
# A flat or unit after the street: ", Apt. 96", " Wohnung 3", ", piso 2".
_UNIT = re.compile(r"(?:,[ \t]*|[ \t]+)(?i:apt\.?|apartment|appartamento|appartement|app\.?"
                   r"|wohnung|whg\.?|piso|planta|flat|unit|suite|ste\.?|lgh|interno|int\.)"
                   r"[ \t]*#?\w{1,6}")
_STREET_RX = re.compile(r"(?<![\w])(?:" + "|".join(_STREET_FORMS) + r")(?![\w])")
# Postal code and city after the street: ", 10115 Berlin", "\n75001 Paris",
# "1012 AB Amsterdam", "114 55 Stockholm", "D-10115 Berlin".
_POST_CITY = re.compile(
    r"(?:,[ \t]*|[ \t]*\n[ \t]*|[ \t]+)(?:[A-Z]{1,2}-)?(?:\d{5}|\d{4}[ \t]?[A-Z]{2}|\d{3} \d{2}"
    rf"|\d{{4}})[ \t]+{_CAP}(?:[ -]{_CAP}){{0,2}}")
_STREET_HINT = re.compile(r"\d")


def intl_street_address(text: str, key_words: str) -> list[tuple]:
    if not _STREET_HINT.search(text):
        return []
    out = []
    for m in _STREET_RX.finditer(text):
        end = m.end()
        unit = _UNIT.match(text, end)
        if unit:
            end = unit.end()
        tail = _POST_CITY.match(text, end)
        if tail:
            end = tail.end()
        out.append(("STREET_ADDRESS", m.start(), end, 0.7))
    return out


# ---------------------------------------------------------------------------
# Passwords and keys written inline
# ---------------------------------------------------------------------------

_SECRET_WORDS = (r"password|passwort|passwd|kennwort|mot\s+de\s+passe|contraseña|contrasena"
                 r"|parola\s+d['’]ordine|wachtwoord|lösenord|api[\s_-]?key|api[\s_-]?schlüssel"
                 r"|api[\s_-]?nyckel|clé\s+api|clave\s+api|chiave\s+api|api[\s_-]?sleutel"
                 r"|secret[\s_-]?key|access[\s_-]?key|access[\s_-]?token|auth[\s_-]?token")
_SECRET_WORD = re.compile(r"(?i)" + _SECRET_WORDS)
# "Password: x", "Passwort = x", "wachtwoord is x", "API key utilizzata: x".
_INLINE_SECRET = re.compile(
    r"(?i)(?:" + _SECRET_WORDS + r")(?:[ \t]+\w{1,12})?[ \t]*(?::|=|[ \t](?:is|ist|est|es|è|är|lautet))"
    r"[ \t]*[\"'“”«]?[ \t]*([^\s\"'“”»<>\[\]{}()|,;]{6,200})")
# <password>x</password>, <ns:apiKey>x</ns:apiKey>
_XML_SECRET = re.compile(r"(?i)<((?:\w+:)?(?:password|passwd|secret|api_?key|access_?token|token))>"
                         r"([^<\s]{4,200})</\1>")


# The same score as the generic "api_key=..." pattern, so when both fire on
# the same key only the longer hit is kept.
_INLINE_SCORE = 0.5


def _secret_like(value: str) -> bool:
    """Has a digit or a symbol, so a plain word ("Required") is not taken."""
    value = value.rstrip(".")
    return (len(value) >= 6 and len(set(value)) > 2
            and any(not c.isalpha() for c in value) and any(c.isalnum() for c in value))


def inline_secret(text: str, key_words: str) -> list[tuple]:
    """A password or API key written after its label in running text, or
    inside an XML element named like one."""
    if not _SECRET_WORD.search(text) and "<" not in text:
        return []
    out = []
    for m in _INLINE_SECRET.finditer(text):
        value = m.group(1).rstrip(".")
        if _secret_like(value):
            out.append(("GENERIC_API_KEY", m.start(1), m.start(1) + len(value), _INLINE_SCORE))
    if "<" in text:
        for m in _XML_SECRET.finditer(text):
            out.append(("GENERIC_API_KEY", m.start(2), m.end(2), _INLINE_SCORE))
    return out


INTL_RECOGNIZERS = (national_id, keyed_id, intl_phone, intl_street_address, inline_secret)

# Keys that make one of these recognizers fire on a value.
INTL_KEY_PATTERNS = (_ID_WORD, _PHONE_WORD)

# Entity types added here; all are PII.
INTL_TYPES = frozenset({"IN_AADHAAR", "IN_PAN", "IT_FISCAL_CODE", "ES_NIF", "ES_NIE", "FR_NIR",
                        "CH_AHV", "UK_NINO", "ID_NUMBER"})
