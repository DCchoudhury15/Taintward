package agentward

import rego.v1

# AgentWard egress policy, the deterministic replacement for AgentRaft's
# D_nec multi-LLM voting committee. This file is the SOURCE OF TRUTH: admins
# edit rules here without rebuilding the SDK, and the collector processor
# evaluates it per span (compile-once / eval-many).
#
# Input shape (one object per span, built by the collector processor from the
# span's `agentward.*` attributes):
#   {
#     "sensitive":    bool,   # agentward.sensitive
#     "classes":      string, # agentward.taint.classes  e.g. "pii,secret"
#     "destination":  string, # agentward.destination    internal|external|llm|log|rag
#     "jurisdiction": string, # agentward.jurisdiction   e.g. "us" | "eu" | "" (Art. 44)
#     "tool":         string, # gen_ai.tool.name
#   }
#
# Output: data.agentward.decision = { "redact": bool, "violations": [...] }

# Sinks where raw sensitive data must not land (egress / leak surfaces).
# internal and rag are handled by Phase 4 redaction, not by the violation gate.
sensitive_sinks := {"external", "llm", "log"}

# Jurisdictions not deemed adequate for EU personal data (GDPR Art. 44).
# A real product maintains an adequacy allowlist (EU Commission decisions +
# SCCs + TIAs); this is the demo set. OpenAI/Anthropic direct APIs process in
# the US (no EU residency) -> "us"; Azure OpenAI gives contractual EU -> "eu".
non_adequate_jurisdictions := {"us"}

# --- helpers ---

has_class(classes, cls) if {
	split(classes, ",")[_] == cls
}

# --- rules ---

# Rule 1: egress, sensitive data reaching an external / llm / log sink.
violation contains {"rule": "pii_egress", "sink": input.destination} if {
	input.sensitive == true
	input.destination in sensitive_sinks
}

# Rule 2: cross-border transfer, PII to a non-adequate jurisdiction.
# Fires IN ADDITION to rule 1 when the sink also sits abroad.
transfer_violation contains {"rule": "transfer", "jurisdiction": input.jurisdiction} if {
	has_class(input.classes, "pii")
	input.jurisdiction in non_adequate_jurisdictions
}

# Always redact raw sensitive values from stored span attributes. SigNoz must
# never store the secret, regardless of whether the sink is a violation.
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