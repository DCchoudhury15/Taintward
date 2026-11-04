"""Cheap language guess for choosing the name model, plus word lists the
name filters use.

``guess(text)`` counts very common function words of English and of six
European languages (German, French, Spanish, Italian, Dutch, Swedish). It is
only used to pick between the English spaCy model and the multilingual one,
so it only has to answer "English or not". Text with no such word (a lone
name, an ID, a number) gets ``None`` and keeps the English model, the same
as before.
"""

from __future__ import annotations

import re

_FUNCTION_WORDS = {
    "en": "the and of to is in for with your you this that are be we please our have will "
          "it on at from as by an was were has not",
    "de": "der die das und ist nicht mit den dem ein eine einen zu von sie wir ihr ihre bitte "
          "für auf ich sich auch des im bei wird werden sind",
    "fr": "le la les et est des une un du pour avec vous nous dans sur pas ce qui que au votre "
          "sont ne cette",
    "es": "el los las y es que en una por para con su sus se del al usted está este esta son",
    "it": "il di che un una per con del della sono ho si gli nel alla questo suo sua è",
    "nl": "het een en van dat niet op zijn met voor je u wij ik er ook bij wordt",
    "sv": "och att det som är på för med av till inte jag har om ett vi",
}
_WORDS = {lang: frozenset(ws.split()) for lang, ws in _FUNCTION_WORDS.items()}
# A whole word: not a piece of a token, an id or a base64 string ("eyJlbCI6").
_WORD = re.compile(r"(?<![\w.@/-])[^\W\d_]+(?![\w@/]|[.-]\w)")

# Only this much of a long value is looked at.
_SAMPLE = 2000


def guess(text: str) -> str | None:
    """"en", another language code, or None when the text has (almost) no
    function word."""
    counts: dict[str, int] = {}
    for w in _WORD.findall(text[:_SAMPLE].lower()):
        for lang, words in _WORDS.items():
            if w in words:
                counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return None
    best = max(counts.values())
    # A tie with English keeps English (the model the rules were built on),
    # and one stray word is not enough to call the text another language.
    if counts.get("en", 0) == best:
        return "en"
    if best < 2:
        return None
    return max(counts, key=counts.get)


# Capitalized words that start sentences, greet, or label a form field in
# these languages. A one-word name hit that is one of them is dropped, and
# they are trimmed off the edge of a longer hit ("Hallo Anna" -> "Anna").
# Words that are also names ("Per", "Best") are not in the list.
NOT_NAMES = frozenset("""
please thank thanks dear hello hi hey regards sincerely kind yours greetings welcome
bitte danke liebe lieber hallo grüße gruß sehr geehrte geehrter herzliche viele freundliche
veuillez merci cher chère bonjour bonsoir salut cordialement madame monsieur
favor gracias estimado estimada hola saludos atentamente querido querida
favore grazie gentile ciao salve cordiali distinti saluti
graag bedankt beste hoi groeten vriendelijke geachte
vänligen tack hej hälsningar
name names nom prénom nombre apellido nome cognome naam achternaam voornaam namn efternamn
vorname nachname
address adresse dirección direccion indirizzo adres adress anschrift
city stadt ville ciudad città stad ort
country land pays país paese
date datum fecha data
number nummer numéro numero número
customer kunde client cliente klant kund
account konto compte cuenta conto rekening
phone telefon téléphone teléfono telefono telefoon
email e-mail mail
subject betreff objet asunto oggetto onderwerp ämne
note hinweis remarque nota opmerking anmärkning
total summe montant importe importo totaal summa
""".split())


# Possessives, personal pronouns and question words. A name hit that is one
# of them, or starts with one ("Meine Gedichte", "Your Account"), is not a
# name. Words that are also common names or surnames (Ella, Han, Mia, Son,
# Vos, Ma, Su, ...) are left out.
NOT_NAME_START = frozenset("""
my your our their his her its we they he she you i me us them
mein meine meinen meinem meiner dein deine deinen deinem deiner sein seine seinen seinem seiner
unser unsere unseren unserem unserer euer eure ihre ihren ihrem ihrer ich du er sie wir ihr
mon mes ton tes notre nos votre leur leurs je il elle nous vous ils elles
mi mis tus sus nuestro nuestra nuestros nuestras vuestro vuestra yo él nosotros vosotros ellos ellas
mio miei mie tuo tua tuoi suo sua suoi nostro nostra nostri vostro vostra io lui noi voi
mijn jouw zijn onze ons uw hun ik jij hij zij wij jullie
mitt mina din ditt dina sitt vår vårt våra ert jag hon vi
what who where when why how was wer wo wann warum wie
quoi qui où quand pourquoi comment qué quién dónde cuándo cómo che chi dove quando perché come
wat waar wanneer waarom hoe vad vem när varför hur
""".split())


# spaCy's stop-word lists for the other languages (shipped with spaCy, no
# model needed): "unsere", "estoy", "alguien", "otro", "qué". Stop words that
# are also first names or surnames are taken out.
_STOP_LANGS = ("de", "fr", "es", "it", "nl", "sv", "pt")
_NAME_LIKE = frozenset("ella han mia son vos ma su lei min sin tu will ben per sara".split())
_stop_words: frozenset | None = None


def stop_words() -> frozenset:
    """The stop words of _STOP_LANGS. Each list is read from its own file:
    importing ``spacy.lang.de`` and the others whole takes about 1.5 s."""
    global _stop_words
    if _stop_words is None:
        import importlib.util
        from pathlib import Path

        words: set = set()
        try:
            spec = importlib.util.find_spec("spacy")
            base = Path(next(iter(spec.submodule_search_locations or ())))
        except Exception:  # noqa: BLE001 - spaCy missing
            base = None
        for lang in _STOP_LANGS if base is not None else ():
            try:
                file_spec = importlib.util.spec_from_file_location(
                    f"_taintward_stop_words_{lang}", base / "lang" / lang / "stop_words.py")
                mod = importlib.util.module_from_spec(file_spec)
                file_spec.loader.exec_module(mod)
                words |= {w.lower() for w in mod.STOP_WORDS}
            except Exception:  # noqa: BLE001 - spaCy changed its layout
                continue
        _stop_words = frozenset(words - _NAME_LIKE)
    return _stop_words
