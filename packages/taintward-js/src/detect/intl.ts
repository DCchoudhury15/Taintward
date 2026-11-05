// Recognizers for data outside the US formats, ported from
// taintward/sdk/recognizers_intl.py (gap G9) and checked against it
// (test/crosscheck.test.ts).
//
// * National ids with a check digit, found anywhere: Indian Aadhaar
//   (Verhoeff), Italian codice fiscale, Spanish DNI / NIE, French NIR, Swiss
//   AHV, UK National Insurance numbers, Indian PAN.
// * Any id next to an id word ("Passnummer:", "numéro de passeport", ...) in
//   English, German, French, Spanish, Italian, Dutch and Swedish, or under
//   such a JSON key. The plain word "id" is not enough.
// * Phone numbers with a + country code, or after a phone word.
// * Street addresses in the usual European forms, with the postal code and
//   city after them.
// * Passwords and API keys written inline ("Passwort: ...").
//
// Python's `re` makes \w, \b and \d Unicode aware; here \w and \b use the
// Unicode word class from patterns.ts. Inline (?i:...) groups are not in
// Node 20, so those words are spelled out with ci().

import { parsePhoneNumberFromString } from "libphonenumber-js/max";
import { B, W, W_IN, type RawHit } from "./patterns.js";

/** Case-insensitive spelling of a regex fragment: each letter becomes [xX]. */
function ci(src: string): string {
  let out = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    if (c === "\\") {
      out += c + (src[i + 1] ?? "");
      i++;
      continue;
    }
    const lo = c.toLowerCase();
    const up = c.toUpperCase();
    out += lo !== up && lo.length === 1 && up.length === 1 ? `[${lo}${up}]` : c;
  }
  return out;
}

/** Python's pattern.match(text, pos): a match starting exactly at pos. */
function matchAt(re: RegExp, text: string, pos: number): RegExpExecArray | null {
  re.lastIndex = pos;
  return re.exec(text);
}

/** Python's pattern.search(text, pos, endpos). */
function searchBetween(re: RegExp, text: string, pos: number, endpos: number): boolean {
  re.lastIndex = Math.max(0, pos);
  return re.exec(text.slice(0, endpos)) !== null;
}

const digitsOf = (s: string) => s.replace(/[^0-9]/g, "");

// ---------------------------------------------------------------------------
// Check digits
// ---------------------------------------------------------------------------

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function verhoeffOk(digits: string): boolean {
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    const d = digits.charCodeAt(digits.length - 1 - i) - 48;
    c = VERHOEFF_D[c]![VERHOEFF_P[i % 8]![d]!]!;
  }
  return c === 0;
}

/** 12 digits, not starting with 0 or 1, Verhoeff check digit. */
export function aadhaarOk(digits: string): boolean {
  return (
    digits.length === 12 && !"01".includes(digits[0]!) &&
    digits !== [...digits].reverse().join("") && verhoeffOk(digits)
  );
}

const CF_ODD_VALUES = [
  1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
  2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
];
const CF_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/** Italian fiscal code: 15 characters plus a check letter. */
export function codiceFiscaleOk(code: string): boolean {
  code = code.toUpperCase();
  if (code.length !== 16) return false;
  let total = 0;
  for (let i = 0; i < 15; i++) {
    const ch = code[i]!;
    if (i % 2 === 0) {
      const k = CF_CHARS.indexOf(ch);
      if (k < 0) return false;
      total += CF_ODD_VALUES[k]!;
    } else {
      total += /[0-9]/.test(ch) ? ch.charCodeAt(0) - 48 : ch.charCodeAt(0) - 65;
    }
  }
  return String.fromCharCode(65 + (total % 26)) === code[15];
}

const DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";

/** Spanish DNI (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter). */
export function dniOk(code: string): boolean {
  code = code.toUpperCase().replace(/-/g, "").replace(/ /g, "");
  if (code.length !== 9) return false;
  let head = code.slice(0, 8);
  if ("XYZ".includes(head[0]!)) head = String("XYZ".indexOf(head[0]!)) + head.slice(1);
  if (!/^[0-9]+$/.test(head)) return false;
  return DNI_LETTERS[Number(head) % 23] === code[8];
}

/** French social security number (NIR): 13 characters + 2-digit key. */
export function nirOk(code: string): boolean {
  code = code.replace(/[\s.-]/g, "").toUpperCase();
  if (code.length !== 15 || !"12".includes(code[0]!)) return false;
  const body = code.slice(0, 13).replaceAll("2A", "19").replaceAll("2B", "18");
  const key = code.slice(13);
  if (!/^[0-9]+$/.test(body) || !/^[0-9]+$/.test(key)) return false;
  const month = Number(code.slice(3, 5));
  if (!((month >= 1 && month <= 12) || (month >= 20 && month <= 42) || (month >= 50 && month <= 99))) {
    return false;
  }
  return 97 - Number(BigInt(body) % 97n) === Number(key);
}

/** Swiss social security number: 756 + 9 digits + EAN-13 check digit. */
export function ahvOk(code: string): boolean {
  const d = digitsOf(code);
  if (d.length !== 13 || !d.startsWith("756")) return false;
  let total = 0;
  for (let i = 0; i < 12; i++) total += (d.charCodeAt(i) - 48) * (i % 2 ? 3 : 1);
  return (10 - (total % 10)) % 10 === d.charCodeAt(12) - 48;
}

const NINO_BAD_PREFIX = new Set(["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"]);

/** UK National Insurance number letter rules. */
export function ninoOk(code: string): boolean {
  code = code.replace(/ /g, "").toUpperCase();
  if (code.length !== 9) return false;
  const p = code.slice(0, 2);
  return (
    !NINO_BAD_PREFIX.has(p) && !"DFIQUV".includes(p[0]!) && !"DFIOQUV".includes(p[1]!) &&
    /^[0-9]{6}$/.test(code.slice(2, 8)) && "ABCD".includes(code[8]!)
  );
}

// ---------------------------------------------------------------------------
// National ids found anywhere
// ---------------------------------------------------------------------------

// Grouped numbers must stand alone: not the first 12 digits of a spaced card
// number or a slice of a spaced IBAN.
const ALONE_BEFORE = `(?<![${W_IN}-])(?<![0-9][ -])`;
const ALONE_AFTER = `(?![${W_IN}-])(?![ -][0-9])`;
const AADHAAR = new RegExp(`${ALONE_BEFORE}[2-9][0-9]{3}([ -])[0-9]{4}\\1[0-9]{4}${ALONE_AFTER}`, "gu");
const AADHAAR_PLAIN = new RegExp(`(?<![${W_IN}-])[2-9][0-9]{11}(?![${W_IN}-])`, "gu");
const CF = new RegExp(
  `(?<![${W_IN}-])[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}` +
    `[A-Z][0-9LMNPQRSTUV]{3}[A-Z](?![${W_IN}-])`,
  "giu",
);
const DNI = new RegExp(`(?<![${W_IN}-])(?:[0-9]{8}|[XYZ][0-9]{7})-?[A-Z](?![${W_IN}-])`, "gu");
const NIR = new RegExp(
  `${ALONE_BEFORE}[12] ?[0-9]{2} ?[0-9]{2} ?(?:[0-9]{2}|2[AB]) ?[0-9]{3} ?[0-9]{3} ?[0-9]{2}${ALONE_AFTER}`,
  "gu",
);
const AHV = new RegExp(`${ALONE_BEFORE}756[. ]?[0-9]{4}[. ]?[0-9]{4}[. ]?[0-9]{2}${ALONE_AFTER}`, "gu");
const NINO = new RegExp(`${ALONE_BEFORE}[A-Z]{2} ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D]${ALONE_AFTER}`, "gu");
const PAN = new RegExp(`(?<![${W_IN}-])[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z](?![${W_IN}-])`, "gu");
const AADHAAR_WORD = new RegExp(`aadhaa?r|${B}uid${B}|आधार`, "giu");
const DIGIT_HINT = /[0-9]{2}/u;

export function nationalId(text: string, keyWords: string): RawHit[] {
  if (!DIGIT_HINT.test(text)) return [];
  const out: RawHit[] = [];
  const hit = (entityType: string, m: RegExpMatchArray) =>
    out.push({ entityType, start: m.index!, end: m.index! + m[0].length, score: 0.6 });
  for (const m of text.matchAll(AADHAAR)) if (aadhaarOk(digitsOf(m[0]))) hit("IN_AADHAAR", m);
  const keyAadhaar = keyWords !== "" && searchBetween(AADHAAR_WORD, keyWords, 0, keyWords.length);
  if (keyAadhaar || searchBetween(AADHAAR_WORD, text, 0, text.length)) {
    for (const m of text.matchAll(AADHAAR_PLAIN)) {
      if (aadhaarOk(m[0]) && (keyAadhaar || searchBetween(AADHAAR_WORD, text, m.index! - 48, m.index!))) {
        hit("IN_AADHAAR", m);
      }
    }
  }
  for (const m of text.matchAll(CF)) if (codiceFiscaleOk(m[0])) hit("IT_FISCAL_CODE", m);
  for (const m of text.matchAll(DNI)) {
    if (dniOk(m[0])) hit("XYZ".includes(m[0][0]!) ? "ES_NIE" : "ES_NIF", m);
  }
  for (const m of text.matchAll(NIR)) if (nirOk(m[0])) hit("FR_NIR", m);
  for (const m of text.matchAll(AHV)) if (ahvOk(m[0])) hit("CH_AHV", m);
  for (const m of text.matchAll(NINO)) if (ninoOk(m[0])) hit("UK_NINO", m);
  for (const m of text.matchAll(PAN)) hit("IN_PAN", m);
  return out;
}

// ---------------------------------------------------------------------------
// Any id next to an id word
// ---------------------------------------------------------------------------

const ID_WORDS =
  // passports
  "passport|passeport|pasaporte|passaporto|paspoort|reisepass|passnummer|passnr|pass-nr" +
  // driving licences
  `|driv${W}*[\\s'’-]*licen[cs]e|licen[cs]e\\s*(?:number|no|nr|#)|führerschein|fahrerlaubnis` +
  "|permis\\s+de\\s+conduire|licencia\\s+de\\s+conducir|carn[eé]t?\\s+de\\s+conducir" +
  "|patente\\s+di\\s+guida|numero\\s+di\\s+patente|rijbewijs|körkort" +
  // identity cards and generic national ids
  `|id[\\s_-]*(?:card|number|no${B}|nr${B}|nummer|numero|número|numéro|kort)|identity\\s*card` +
  "|national[\\s_-]*id|personalausweis|ausweisnummer|carte\\s+d['’]identit|documento\\s+de\\s+identidad" +
  "|carta\\s+d['’]identit|identiteitskaart|identitetskort|legitimation" +
  // social security, tax and citizen numbers
  "|social[\\s_-]*security|sécurité\\s+sociale|securite\\s+sociale|seguridad\\s+social" +
  "|previdenza\\s+sociale|sozialversicherung|personnummer|personnr|samordningsnummer" +
  `|burgerservicenummer|sofinummer|codice\\s+fiscale|codice_fiscale|tax[\\s_-]*(?:id|number|no${B})` +
  "|steuer[\\s-]*id|steuernummer|steueridentifikationsnummer|identifiant\\s+fiscal" +
  "|num[ée]ro\\s+fiscal|n[uú]mero\\s+fiscal|national\\s+insurance|aadhaa?r";
export const ID_WORD = new RegExp(`(?:${ID_WORDS})`, "giu");
// Short acronyms only count in capitals ("DNI", not "dni" inside a word).
const ID_ACRONYM =
  /(?<![A-Za-z])(?:SSN|DNI|NIE|NIF|CNI|BSN|NIR|PAN|AHV|AVS|NINO|TIN|CPF|PESEL|CURP|RUT|NHS)(?![A-Za-z])/gu;
// An id: letters and digits, maybe split by spaces, dots, dashes or slashes,
// with at least four digits. Upper case only, so words are not picked up.
const ID_VALUE = new RegExp(
  `(?<![${W_IN}./-])(?=[A-Z0-9./ -]*[0-9][A-Z0-9./ -]*[0-9][A-Z0-9./ -]*[0-9][A-Z0-9./ -]*[0-9])` +
    `[A-Z0-9]{1,20}(?:[ ./-][A-Z0-9]{1,12}){0,5}(?![${W_IN}-]|[./][A-Z0-9])`,
  "gu",
);
// A value that starts with a date ("2024-03-02 10:30", "02.03.2024 10").
const STARTS_DATE = /^(?:[0-9]{4}[./-][0-9]{1,2}[./-][0-9]{1,2}|[0-9]{1,2}[./-][0-9]{1,2}[./-][0-9]{2,4})(?![0-9])/u;
const ID_WINDOW = 40;

// A US social security number is left to the SSN recognizers.
const US_SSN_WORD = /^(?:ssn|social[\s_-]*security)$/iu;
const US_SSN_SHAPE = /^[0-9]{3}-?[0-9]{2}-?[0-9]{4}$/u;

function allMatches(re: RegExp, text: string, lo: number, hi: number): string[] {
  const out: string[] = [];
  const slice = text.slice(0, hi);
  re.lastIndex = lo;
  for (let m = re.exec(slice); m !== null; m = re.exec(slice)) {
    out.push(m[0]);
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

/** The id words in the same line, at most ID_WINDOW characters before. */
function idWords(text: string, start: number): string[] {
  let lo = Math.max(0, start - ID_WINDOW);
  const nl = text.lastIndexOf("\n", start - 1);
  if (nl >= lo) lo = nl + 1;
  return [...allMatches(ID_WORD, text, lo, start), ...allMatches(ID_ACRONYM, text, lo, start)];
}

function keyIdWords(keyWords: string): string[] {
  if (!keyWords) return [];
  const spaced = keyWords.replace(/_/g, " ");
  const upper = keyWords.toUpperCase();
  return [...allMatches(ID_WORD, spaced, 0, spaced.length), ...allMatches(ID_ACRONYM, upper, 0, upper.length)];
}

// Python's str.strip() whitespace set.
const STRIP_RE = /^[\s\x1c-\x1f\x85]+|[\s\x1c-\x1f\x85]+$/gu;

/** An id-shaped value right after an id word, or under an id key. */
export function keyedId(text: string, keyWords: string): RawHit[] {
  const keyFound = keyIdWords(keyWords);
  if (
    keyFound.length === 0 &&
    !searchBetween(ID_WORD, text, 0, text.length) &&
    !searchBetween(ID_ACRONYM, text, 0, text.length)
  ) {
    return [];
  }
  const out: RawHit[] = [];
  const stripped = text.replace(STRIP_RE, "").length;
  for (const m of text.matchAll(ID_VALUE)) {
    const value = m[0].replace(STRIP_RE, "");
    if (value.replace(/[^A-Z0-9]/g, "").length < 5 || STARTS_DATE.test(value)) continue;
    const words = keyFound.length > 0 && value.length >= stripped - 2 ? keyFound : idWords(text, m.index!);
    if (words.length === 0) continue;
    if (US_SSN_SHAPE.test(value) && words.every((w) => US_SSN_WORD.test(w))) continue;
    out.push({ entityType: "ID_NUMBER", start: m.index!, end: m.index! + value.length, score: 0.6 });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Phone numbers
// ---------------------------------------------------------------------------

const INTL_PHONE = new RegExp(`(?<![${W_IN}+])\\+[0-9]{1,3}(?:[ .\\-/]?\\(?[0-9]{1,5}\\)?){1,7}(?!${W})`, "gu");
export const PHONE_WORD = new RegExp(
  `(?:phone|telephone|tel${B}|tel\\.|mobile|cell|fax|whatsapp|sms|contact|call${B}|calling` +
    `|telefon|rufnummer|handy|mobil|anrufen|rufen|téléphone|tél${B}|tél\\.|portable|appeler` +
    "|contacter|teléfono|telefono|móvil|celular|llamar|contactar|cellulare|chiamare|chiamaci" +
    `|contattare|contattaci|telefoon|mobiel|gsm|bellen|mobilnummer|mobiltelefon|ringa|ring${B})`,
  "giu",
);
// A local number: starts with 0, or is written in groups ("(797) 230 2377").
const LOCAL_PHONE = new RegExp(
  `(?<![${W_IN}+.,/-])(?:\\(?0[0-9]{1,4}\\)?(?:[ .\\-/]?[0-9]{2,6}){1,5}` +
    `|\\(?[1-9][0-9]{1,3}\\)?(?:[ .\\-/][0-9]{2,6}){2,5})(?![${W_IN}-]|[.,][0-9])`,
  "gu",
);
const PHONE_WINDOW = 40;

function phonePossible(number: string): boolean {
  try {
    return parsePhoneNumberFromString(number)?.isPossible() ?? false;
  } catch {
    return false;
  }
}

/** +CC numbers (any country), and local numbers after a phone word or under
 * a phone key. */
export function intlPhone(text: string, keyWords: string): RawHit[] {
  const out: RawHit[] = [];
  if (text.includes("+")) {
    for (const m of text.matchAll(INTL_PHONE)) {
      const n = digitsOf(m[0]).length;
      if ((n >= 9 && n <= 15) || (n === 8 && phonePossible(m[0]))) {
        out.push({ entityType: "PHONE_NUMBER", start: m.index!, end: m.index! + m[0].length, score: 0.6 });
      }
    }
  }
  const keyHit = keyWords !== "" && searchBetween(PHONE_WORD, keyWords, 0, keyWords.length);
  if (keyHit || searchBetween(PHONE_WORD, text, 0, text.length)) {
    for (const m of text.matchAll(LOCAL_PHONE)) {
      const n = digitsOf(m[0]).length;
      if (n < 8 || n > 13 || STARTS_DATE.test(m[0].replace(/^\(+/, ""))) continue;
      if (keyHit || searchBetween(PHONE_WORD, text, m.index! - PHONE_WINDOW, m.index!)) {
        out.push({ entityType: "PHONE_NUMBER", start: m.index!, end: m.index! + m[0].length, score: 0.6 });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Street addresses
// ---------------------------------------------------------------------------

const CAP = `[A-ZÀ-ÖØ-Þ][${W_IN}À-ÖØ-öø-ÿ'’.-]*`;
const HOUSE = `[0-9]{1,5}(?:[ \\t]?[a-zA-Z](?![${W_IN}]))?(?:[ \\t]?(?:bis|ter))?`;
// Words of one address stay on one line; only the postal code and city may
// follow on the next line.
const SP = "[ \\t]{1,2}";
const GLUED =
  "(?:straße|strasse|str\\.|weg|platz|gasse|allee|damm|chaussee" +
  "|straat|laan|plein|gracht|kade|singel|dijk|steeg" +
  "|gatan|vägen|gränd|torget|backe|stigen|platsen|allén)";
const PREFIX = `(?:${ci(
  "rue|avenue|av\\.|boulevard|bd|place|chemin|allée|impasse|quai|route|cours|via|viale" +
    "|piazza|piazzale|corso|largo|vicolo|strada|calle|c/|avenida|avda\\.|plaza|paseo|camino" +
    "|carrera|ronda|travesía|rambla|carretera|urbanización|rua|praça",
)})`;
const PARTICLES = "(?:(?:de|du|des|la|le|les|l['’]|del|della|di|dei|degli|las|los|el)[ \\t]*){0,3}";
const EN_SUFFIX = "(?:Street|Avenue|Road|Lane|Drive|Boulevard|Way|Court|Place)";
const STREET_FORMS = [
  `${CAP}${GLUED}${SP}${HOUSE}`,
  `(?:${CAP}${SP}){1,3}(?:Straße|Strasse|Str\\.|Weg|Platz|Gasse|Allee|${EN_SUFFIX})${SP}${HOUSE}`,
  `${HOUSE}${SP}${CAP}${GLUED}`,
  `${HOUSE},?${SP}${PREFIX}${SP}${PARTICLES}${CAP}(?:${SP}${CAP}){0,3}`,
  `${PREFIX}${SP}${PARTICLES}${CAP}(?:(?:${SP}|-)${CAP}){0,3},?${SP}(?:n[º°.]?[ \\t]*)?${HOUSE}`,
];
const UNIT = new RegExp(
  `(?:,[ \\t]*|[ \\t]+)${ci(
    "(?:apt\\.?|apartment|appartamento|appartement|app\\.?|wohnung|whg\\.?|piso|planta|flat|unit" +
      "|suite|ste\\.?|lgh|interno|int\\.)",
  )}[ \\t]*#?${W}{1,6}`,
  "yu",
);
const STREET_RX = new RegExp(`(?<!${W})(?:${STREET_FORMS.join("|")})(?!${W})`, "gu");
const POST_CITY = new RegExp(
  "(?:,[ \\t]*|[ \\t]*\\n[ \\t]*|[ \\t]+)(?:[A-Z]{1,2}-)?(?:[0-9]{5}|[0-9]{4}[ \\t]?[A-Z]{2}|[0-9]{3} [0-9]{2}" +
    `|[0-9]{4})[ \\t]+${CAP}(?:[ -]${CAP}){0,2}`,
  "yu",
);

export function intlStreetAddress(text: string): RawHit[] {
  if (!/[0-9]/.test(text)) return [];
  const out: RawHit[] = [];
  for (const m of text.matchAll(STREET_RX)) {
    let end = m.index! + m[0].length;
    const unit = matchAt(UNIT, text, end);
    if (unit) end += unit[0].length;
    const tail = matchAt(POST_CITY, text, end);
    if (tail) end += tail[0].length;
    out.push({ entityType: "STREET_ADDRESS", start: m.index!, end, score: 0.7 });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Passwords and keys written inline
// ---------------------------------------------------------------------------

const SECRET_WORDS =
  "password|passwort|passwd|kennwort|mot\\s+de\\s+passe|contraseña|contrasena" +
  "|parola\\s+d['’]ordine|wachtwoord|lösenord|api[\\s_-]?key|api[\\s_-]?schlüssel" +
  "|api[\\s_-]?nyckel|clé\\s+api|clave\\s+api|chiave\\s+api|api[\\s_-]?sleutel" +
  "|secret[\\s_-]?key|access[\\s_-]?key|access[\\s_-]?token|auth[\\s_-]?token";
const SECRET_WORD = new RegExp(SECRET_WORDS, "iu");
const INLINE_SECRET = new RegExp(
  `(?:${SECRET_WORDS})(?:[ \\t]+${W}{1,12})?[ \\t]*(?::|=|[ \\t](?:is|ist|est|es|è|är|lautet))` +
    "[ \\t]*[\"'“”«]?[ \\t]*([^\\s\"'“”»<>\\[\\]{}()|,;]{6,200})",
  "giu",
);
const XML_SECRET =
  /<((?:\w+:)?(?:password|passwd|secret|api_?key|access_?token|token))>([^<\s]{4,200})<\/\1>/giu;
// The same score as the generic "api_key=..." pattern, so when both fire on
// the same key only the longer hit is kept.
const INLINE_SCORE = 0.5;

/** Has a digit or a symbol, so a plain word ("Required") is not taken. */
function secretLike(value: string): boolean {
  value = value.replace(/\.+$/u, "");
  const chars = [...value];
  return (
    chars.length >= 6 && new Set(chars).size > 2 &&
    chars.some((c) => !/\p{Alphabetic}/u.test(c)) && chars.some((c) => /[\p{Alphabetic}\p{N}]/u.test(c))
  );
}

export function inlineSecret(text: string): RawHit[] {
  if (!SECRET_WORD.test(text) && !text.includes("<")) return [];
  const out: RawHit[] = [];
  for (const m of text.matchAll(INLINE_SECRET)) {
    const value = m[1]!.replace(/\.+$/u, "");
    if (!secretLike(value)) continue;
    const start = m.index! + m[0].length - m[1]!.length;
    out.push({ entityType: "GENERIC_API_KEY", start, end: start + value.length, score: INLINE_SCORE });
  }
  if (text.includes("<")) {
    for (const m of text.matchAll(XML_SECRET)) {
      const start = m.index! + m[0].indexOf(">") + 1;
      out.push({ entityType: "GENERIC_API_KEY", start, end: start + m[2]!.length, score: INLINE_SCORE });
    }
  }
  return out;
}

export const INTL_RECOGNIZERS: ReadonlyArray<(text: string, key: string) => RawHit[]> = [
  nationalId,
  keyedId,
  intlPhone,
  (t) => intlStreetAddress(t),
  (t) => inlineSecret(t),
];

/** Entity types added here; all are PII. */
export const INTL_TYPES: ReadonlySet<string> = new Set([
  "IN_AADHAAR", "IN_PAN", "IT_FISCAL_CODE", "ES_NIF", "ES_NIE", "FR_NIR", "CH_AHV", "UK_NINO", "ID_NUMBER",
]);
