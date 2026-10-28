// Sink destination classes, the same strings as the Python SDK and the
// collector policy.

export const DEST_INTERNAL = "internal";
export const DEST_EXTERNAL = "external";
export const DEST_LLM = "llm";
export const DEST_LOG = "log";
export const DEST_RAG = "rag";

export type Destination = "internal" | "external" | "llm" | "log" | "rag";

export const DESTINATIONS: readonly Destination[] = ["internal", "external", "llm", "log", "rag"];

/** Sinks where a tainted chain is recorded as a violation. */
export const EGRESS_SINKS: ReadonlySet<string> = new Set(["external", "llm", "log"]);

export function checkDestination(d: string, where = "destination"): Destination {
  if (!(DESTINATIONS as readonly string[]).includes(d)) {
    throw new Error(`taintward: unknown ${where} ${JSON.stringify(d)}; use one of ${DESTINATIONS.join(", ")}`);
  }
  return d as Destination;
}
