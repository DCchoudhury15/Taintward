package taintward

import rego.v1

# Taintward egress policy, the deterministic replacement for AgentRaft's
# D_nec multi-LLM voting committee. This file is the SOURCE OF TRUTH: admins
# edit rules here without rebuilding the SDK, and the collector processor
# evaluates it per span (compile-once / eval-many).
#
# Input shape (one object per span, built by the collector processor from the
# span's `taintward.*` attributes):
#   {
#     "sensitive":    bool,   # taintward.sensitive
#     "classes":      string, # taintward.taint.classes  e.g. "pii,secret"
#     "destination":  string, # taintward.destination    internal|external|llm|log|rag
#     "jurisdiction": string, # taintward.jurisdiction   e.g. "us" | "eu" | "" (Art. 44)
#     "tool":         string, # gen_ai.tool.name
#   }
#
# String fields are matched case-insensitively ("US" is the same as "us"):
# the policy lower-cases them itself, and the processor also sends them
# lower-cased.
#
# Output: data.taintward.decision = { "redact": bool, "violations": [...] }
#
# The processor checks at startup that this file is `package taintward` and
# defines `decision` and `redact`, then probes it with two sample inputs. Keep
# `default redact := false`: without it `decision` is undefined for spans
# that are not sensitive, and no violation would be reported for them.
# (violation, transfer_violation and deny are multi-value rules: they are
# already the empty set when nothing matches, and Rego does not allow a
# default on them.)

# Sinks where raw sensitive data must not land (egress / leak surfaces).
# internal and rag are handled by Phase 4 redaction, not by the violation gate.
sensitive_sinks := {"external", "llm", "log"}

# Jurisdictions not deemed adequate for EU personal data (GDPR Art. 44).
# A real product maintains an adequacy allowlist (EU Commission decisions +
# SCCs + TIAs); this is the demo set. OpenAI/Anthropic direct APIs process in
# the US (no EU residency) -> "us"; Azure OpenAI gives contractual EU -> "eu".
non_adequate_jurisdictions := {"us"}

# --- helpers ---

norm(s) := lower(trim_space(s))

has_class(classes, cls) if {
	norm(split(classes, ",")[_]) == cls
}

destination := norm(object.get(input, "destination", ""))

jurisdiction := norm(object.get(input, "jurisdiction", ""))

# --- rules ---

# Rule 1: egress, sensitive data reaching an external / llm / log sink.
violation contains {"rule": "pii_egress", "sink": destination} if {
	input.sensitive == true
	destination in sensitive_sinks
}

# Rule 2: cross-border transfer, PII to a non-adequate jurisdiction.
# Fires IN ADDITION to rule 1 when the sink also sits abroad.
transfer_violation contains {"rule": "transfer", "jurisdiction": jurisdiction} if {
	has_class(object.get(input, "classes", ""), "pii")
	jurisdiction in non_adequate_jurisdictions
}

# Always redact raw sensitive values from stored span attributes. SigNoz must
# never store the secret, regardless of whether the sink is a violation.
# (The processor's regex backstop also runs on every span, whatever this says.)
default redact := false

redact if {
	input.sensitive == true
}

# All deny-worthy findings on this span (violations + transfers).
deny contains v if {
	v := violation[_]
}

deny contains v if {
	v := transfer_violation[_]
}

# Single aggregate decision the processor reads.
decision := {
	"redact": redact,
	"violations": deny,
}
