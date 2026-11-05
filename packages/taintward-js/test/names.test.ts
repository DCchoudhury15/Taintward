// Person names in TypeScript: found only with a title, label, greeting,
// sign-off or name key (the Python SDK uses spaCy NER instead).

import { describe, expect, it } from "vitest";
import { detectText } from "../src/detect/index.js";
import { redactPayload } from "../src/redact.js";

const names = (text: string, key?: string) =>
  detectText(text, key ? { key } : {})
    .filter((d) => d.entityType === "PERSON")
    .map((d) => text.slice(d.start, d.end));

describe("person names", () => {
  it.each([
    ["Anna Roth", "first_name", "Anna Roth"],
    ["Jean-Luc O'Neil", "customerName", "Jean-Luc O'Neil"],
    ["Müller", "nachname", "Müller"],
    ["Maria de la Cruz", "full_name", "Maria de la Cruz"],
    ["Ludwig van Beethoven", "name", "Ludwig van Beethoven"],
    ["Ronald McDonald", "contact_name", "Ronald McDonald"],
  ])("value %s under key %s", (text, key, want) => {
    expect(names(text, key)).toEqual([want]);
  });

  it.each([
    ["report.pdf", "file_name"],
    ["Acme GmbH", "company_name"],
    ["gpt-4.1", "model_name"],
    ["Anna Roth", "username"],
    ["anna roth", "first_name"],
    ["Customer", "name"],
    ["Anna Roth 42", "name"],
  ])("not a name: %s under %s", (text, key) => {
    expect(names(text, key)).toEqual([]);
  });

  it.each([
    ["Please call Dr. Anna Roth tomorrow.", "Anna Roth"],
    ["Termin mit Frau Weber am Montag", "Weber"],
    ["Rendez-vous avec Mme Dupont", "Dupont"],
    ["Name: Jana Novak, Passnummer: C01X00T47", "Jana Novak"],
    ["Nom : Lucie Martin\nVille : Lyon", "Lucie Martin"],
    ["Dear Anna,\nthanks for the call.", "Anna"],
    ["Hallo Jan!\nHier die Unterlagen.", "Jan"],
    ["Hola Lucía Fernández,\n", "Lucía Fernández"],
    ["See you then.\n\nBest regards,\nAnna Roth", "Anna Roth"],
    ["Mit freundlichen Grüßen\nKlaus Becker", "Klaus Becker"],
  ])("in text: %s", (text, want) => {
    expect(names(text)).toEqual([want]);
  });

  it.each([
    "Dear Team,\nthe build is green.",
    "Hi all, the deploy is done.",
    "Hello there!",
    "Name: required",
    "Customer: none",
    "Best regards,\nThe Support Team",
    "Anna Roth wrote the report.", // no title, label or greeting: missed on purpose
    "Thanks,\nsee you",
    "Name: Anna Roth 42", // not only name words up to the comma or line end
  ])("not a name: %s", (text) => {
    expect(names(text)).toEqual([]);
  });

  it("is masked for every destination", () => {
    const out = redactPayload({ first_name: "Anna", note: "Dear Anna Roth," }, "external");
    expect(JSON.stringify(out)).not.toContain("Anna");
  });
});
