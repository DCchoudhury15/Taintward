// Taintward for TypeScript: find PII and secrets, redact them per
// destination, and give the LLM placeholders it can work with.
//
// The detector is a port of the Python SDK's pattern recognizers and is
// checked against it (test/crosscheck.test.ts). Names and places (spaCy NER
// in Python) are not detected here.

export {
  MASK_TOKEN,
  THRESHOLD,
  classify,
  detectAll,
  detectPayload,
  detectText,
  fingerprint,
  maskString,
  maskText,
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
export { maskPayload, redactPayload, redactString, redactText, redactValue, type InternalMode, type RedactOptions } from "./redact.js";
