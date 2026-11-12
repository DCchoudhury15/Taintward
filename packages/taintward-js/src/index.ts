// Taintward for TypeScript: find PII and secrets, redact them per
// destination, and give the LLM placeholders it can work with.
//
// The detector is a port of the Python SDK's pattern recognizers and is
// checked against it (test/crosscheck.test.ts). Names (spaCy NER in Python)
// are found here only after a title, label, greeting or sign-off, or under a
// name key; places are not looked for.

export {
  MASK_TOKEN,
  OVERSIZE,
  THRESHOLD,
  UNSCANNED,
  classify,
  detectAll,
  detectPayload,
  detectText,
  fingerprint,
  maskString,
  maskText,
  maxChars,
  normalizeForDetection,
  type DetectOptions,
  type Detection,
  type Sensitivity,
} from "./detect/index.js";
export { DESTINATIONS, EGRESS_SINKS, checkDestination, type Destination } from "./destinations.js";
export {
  INSTRUCTION,
  PlaceholderMap,
  PlaceholderRestoreError,
  StreamRestorer,
  inUrl,
  instructionFor,
  labelFor,
  type KnownSpan,
  type PlaceholderMapOptions,
  type RestoreReport,
} from "./placeholders.js";
export {
  getTokenizer,
  maskPayload,
  redactPayload,
  redactString,
  redactText,
  redactValue,
  type InternalMode,
  type RedactOptions,
} from "./redact.js";
export { FF1, ff1MinLen } from "./ff1.js";
export { Tokenizer, type TokenVault, type TokenizerOptions } from "./tokens.js";
export { protectAnthropic, protectOpenAI, type ProtectClientOptions } from "./clients.js";
