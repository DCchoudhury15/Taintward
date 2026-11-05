// Person names, TypeScript only.
//
// The Python SDK finds names with spaCy NER, which has no equivalent here.
// This finds a name only where something says it is one, so it misses names
// in running text but rarely fires on other words:
//
// * the value under a name key (`first_name`, `customerName`, `nachname`),
// * after a title ("Dr. Anna Roth", "Frau Weber", "M. Dupont"),
// * after a label ("Name: Anna Roth", "Nom : Dupont"),
// * after a greeting at the start of a line ("Dear Anna,", "Hallo Jan!"),
// * alone on the line after a sign-off ("Best regards,\nAnna Roth").
//
// A name is one to four capitalized words (letters, hyphens and
// apostrophes), never a word from the small list of non-names below.

import type { RawHit } from "./patterns.js";

// "Anna", "McDonald", "O'Neil", "Jean-Luc"
const WORD =
  "\\p{Lu}(?:[\\p{Ll}\\p{M}]+(?:\\p{Lu}[\\p{Ll}\\p{M}]+)?|['’]\\p{Lu}[\\p{Ll}\\p{M}]+)" +
  "(?:[-'’]\\p{Lu}?[\\p{Ll}\\p{M}]+)*";
// Particles inside a name: "Ludwig van Beethoven", "Maria de la Cruz".
const PARTICLE = "(?:van|von|der|den|de|del|della|di|da|du|la|le|ten|ter|zu|y|e|bin|al)";
const NAME = `${WORD}(?:[ \\t]+(?:${PARTICLE}[ \\t]+){0,2}${WORD}){0,3}`;

// Capitalized words that follow a greeting or label but are not names.
const NOT_NAMES = new Set(
  (
    "team all everyone everybody sir madam madame sirs customer customers colleague colleagues " +
    "friend friends folks guys there support sales admin user users client clients member members " +
    "manager management hr it ops staff partner partners reader readers world morning afternoon " +
    "evening name names unknown none null undefined required optional n/a tbd test example " +
    "kollegen kolleginnen damen herren zusammen alle leute équipe tous amigos todos equipo " +
    "tutti ragazzi collega colleghi allemaal iedereen alla hej"
  ).split(" "),
);

function isName(text: string): boolean {
  const words = text.split(/[ \t]+/u);
  return !words.some((w) => NOT_NAMES.has(w.toLowerCase()));
}

// Keys whose value is a person's name (any case, with or without `_`, so
// `customerName` too). Not file, product, company, tool or model names, and
// not user names (account handles).
const NAME_KEY = new RegExp(
  "^(?:" +
    [
      "name", "full[_ -]?name", "first[_ -]?name", "last[_ -]?name", "middle[_ -]?name",
      "given[_ -]?name", "family[_ -]?name", "sur[_ -]?name", "maiden[_ -]?name", "legal[_ -]?name",
      "(?:customer|client|patient|contact|employee|recipient|sender|guest|passenger|applicant" +
        "|holder|card[_ -]?holder|account[_ -]?holder|beneficiary|owner|person|member|student" +
        "|parent|spouse|emergency[_ -]?contact)[_ -]?(?:full[_ -]?)?name",
      "cardholder", "account[_ -]?holder", "beneficiary",
      "vorname", "nachname", "familienname", "nom", "pr[ée]nom", "nom[_ -]?de[_ -]?famille",
      "nombre", "apellidos?", "nome", "cognome", "voornaam", "achternaam", "f[öo]rnamn", "efternamn",
    ].join("|") +
    ")$",
  "iu",
);

const WHOLE_NAME = new RegExp(`^[\\s"']*(${NAME})[\\s"'.]*$`, "u");

function keyedName(text: string, key: string): RawHit[] {
  if (!key || !NAME_KEY.test(key)) return [];
  const m = WHOLE_NAME.exec(text);
  if (!m || !isName(m[1]!)) return [];
  const start = text.indexOf(m[1]!);
  return [{ entityType: "PERSON", start, end: start + m[1]!.length, score: 0.6 }];
}

const TITLE =
  "(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof|Herr|Frau|Fr\\.|Hr\\.|M\\.|Mme|Mlle|Sr|Sra|Srta|Don|Doña" +
  "|Sig|Sig\\.ra|Sig\\.na|Dott|Dott\\.ssa|Dhr|Mevr|Mw)";
const TITLED = new RegExp(`(?<![\\p{L}])${TITLE}\\.?[ \\t]+(${NAME})`, "gu");

const LABEL =
  "(?:Name|Full name|First name|Last name|Surname|Customer|Patient|Contact|Recipient|Sender" +
  "|Cardholder|Account holder|Employee|Vorname|Nachname|Kunde|Kundin|Patientin|Empfänger" +
  "|Nom|Prénom|Nom de famille|Destinataire|Nombre|Apellidos?|Destinatario|Nome|Cognome" +
  "|Naam|Voornaam|Achternaam|Namn|Förnamn|Efternamn|Mottagare)";
const LABELED = new RegExp(`(?<![\\p{L}])${LABEL}[ \\t]*:[ \\t]*(${NAME})(?=[ \\t]*(?:$|[,;\\n(]))`, "gmu");

const GREETING =
  "(?:Dear|Hi|Hello|Hey|Good morning|Good afternoon|Liebe|Lieber|Hallo|Guten Tag|Sehr geehrte" +
  "|Sehr geehrter|Bonjour|Cher|Chère|Salut|Hola|Estimado|Estimada|Querido|Querida|Ciao|Gentile" +
  "|Caro|Cara|Buongiorno|Beste|Hoi|Hej|Kära)";
const GREETED = new RegExp(
  `^[ \\t]*${GREETING}(?:[ \\t]+${TITLE}\\.?)?[ \\t]+(${NAME})[ \\t]*(?=[,!:\\n]|$)`,
  "gmu",
);

const SIGNOFF =
  "(?:Best regards|Kind regards|Regards|Best wishes|Best|Thanks|Thank you|Many thanks|Cheers" +
  "|Sincerely|Yours sincerely|Yours truly|Mit freundlichen Grüßen|Viele Grüße|Beste Grüße|Gruß" +
  "|Liebe Grüße|Cordialement|Bien à vous|Bien cordialement|Saludos|Atentamente|Un saludo" +
  "|Cordiali saluti|Distinti saluti|Saluti|Met vriendelijke groet|Groeten|Med vänliga hälsningar" +
  "|Vänliga hälsningar|Hälsningar|MfG)";
const SIGNED = new RegExp(`^[ \\t]*${SIGNOFF}[ \\t]*[,!.]?[ \\t]*\\r?\\n[ \\t]*(${NAME})[ \\t]*$`, "gmu");

function groupHits(re: RegExp, text: string): RawHit[] {
  const out: RawHit[] = [];
  for (const m of text.matchAll(re)) {
    const name = m[1]!;
    if (!isName(name)) continue;
    const start = m.index! + m[0].lastIndexOf(name);
    out.push({ entityType: "PERSON", start, end: start + name.length, score: 0.6 });
  }
  return out;
}

const HINT = /\p{Lu}\p{Ll}/u;

/** Person names with a title, label, greeting, sign-off or name key. */
export function personName(text: string, key: string): RawHit[] {
  if (!HINT.test(text)) return [];
  return [
    ...keyedName(text, key),
    ...groupHits(TITLED, text),
    ...groupHits(LABELED, text),
    ...groupHits(GREETED, text),
    ...groupHits(SIGNED, text),
  ];
}
