"""Compliance mappings: which Taintward controls support which requirement of
GDPR, the EU AI Act, HIPAA and SOC 2, what a report shows as evidence for
each, and where the limits are.

The mapping says what Taintward does toward a requirement. It is not legal
advice, and running Taintward does not by itself make a system compliant:
most requirements also need things outside Taintward (contracts, purposes,
retention rules, access control, training data governance, ...). Each row
says how much Taintward covers:

    supports     Taintward does the technical part of what the requirement asks
                 for the data that goes through it
    partly       it helps (evidence, scoping, one part of the requirement)
    not covered  listed so nobody assumes it is

The same table drives section 11 of the report (``--frameworks``) and
docs/compliance.md (``python -m taintward.evidence.compliance``; a test keeps
the page in sync).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

SUPPORTS = "supports"
PARTLY = "partly"
NOT_COVERED = "not covered"
LEVELS = (SUPPORTS, PARTLY, NOT_COVERED)


@dataclass(frozen=True)
class Control:
    id: str
    name: str
    what: str
    code: str


@dataclass(frozen=True)
class Requirement:
    framework: str
    ref: str
    title: str
    controls: tuple[str, ...]
    level: str
    how: str
    limits: str
    # Which part of the report holds evidence for it (see _evidence).
    report: str = ""


CONTROLS: dict[str, Control] = {c.id: c for c in (
    Control("detect", "Sensitive data detection",
            "finds PII and secrets in tool and model inputs and outputs (patterns with "
            "checksums, context rules, spaCy NER) and carries a taint label along the run",
            "taintward/sdk/detect.py, taintward/sdk/taint.py"),
    Control("redact-egress", "Redaction before data leaves",
            "redacts each call's input for its destination before the call runs: one-way "
            "masks for external, log and rag sinks",
            "taintward/sdk/instrumentation.py, taintward/sdk/redact.py"),
    Control("placeholders", "Placeholders for the LLM",
            "the model gets <PERSON_1> style placeholders instead of values; the answer is "
            "restored for the caller, never for links in it",
            "taintward/sdk/placeholders.py"),
    Control("tokens", "Reversible tokens for internal sinks",
            "internal stores get format-preserving FF1 tokens; the original is kept in the "
            "vault",
            "taintward/sdk/ff1.py, taintward/sdk/redact.py"),
    Control("vault-encryption", "Originals encrypted at rest",
            "vault rows are sealed with AES-GCM, the token as associated data; subjects are "
            "indexed with an HMAC blind index",
            "taintward/sdk/vault.py"),
    Control("keys", "Key management",
            "key rings with KMS-wrapped keys (AWS KMS, Google Cloud KMS, Vault Transit), "
            "KMS-only mode, scheduled rotation and reseal",
            "taintward/sdk/keys.py, deploy/helm/taintward/templates/key-rotation.yaml"),
    Control("erasure", "Erasure by subject",
            "deletes every vault row of a subject (all key generations) and a "
            "conversation's placeholders",
            "taintward/sdk/vault.py (forget_subject), taintward/sdk/placeholders.py"),
    Control("destinations", "Destination and jurisdiction policy",
            "each tool has a destination class and jurisdiction; unmapped tools are external; "
            "a Rego policy flags egress and cross-border transfers",
            "taintward/sdk/integrations/__init__.py, collector/policy/pii_egress.rego"),
    Control("gateway", "MCP gateway",
            "redacts or blocks MCP tool calls after a session has seen sensitive data; pins "
            "tool definitions",
            "taintward/gateway/"),
    Control("telemetry", "Masked telemetry",
            "span inputs and outputs are stored masked; the collector scrubs regex types "
            "and drops framework attributes that hold real values",
            "taintward/sdk/instrumentation.py, collector/processor/taintpolicy/"),
    Control("records", "Per-call records",
            "every wrapped tool and model call is an OpenTelemetry span with its "
            "destination, taint, decision and outcome",
            "taintward/sdk/instrumentation.py"),
    Control("evidence-log", "Tamper-evident evidence log",
            "violations go into a Merkle log with signed checkpoints, so a record that is "
            "changed or removed later is detected",
            "taintward/evidence/merkle.py, taintward/evidence/checkpoint.py"),
    Control("reversal-audit", "Audit of every reversal",
            "each token reversal and placeholder restore by code is recorded (span event "
            "and taintward.audit log), with the key id and the caller, never the value",
            "taintward/sdk/redact.py (record_reversal)"),
    Control("report", "Sensitive data flow report",
            "counts calls, sensitive calls, destinations, violations, transfers and "
            "recipients for a time window, checks what was sent for raw values, and "
            "verifies the evidence log",
            "taintward/evidence/report.py"),
)}


FRAMEWORKS: dict[str, str] = {
    "gdpr": "GDPR (Regulation (EU) 2016/679)",
    "eu-ai-act": "EU AI Act (Regulation (EU) 2024/1689)",
    "hipaa": "HIPAA (45 CFR Parts 160 and 164)",
    "soc2": "SOC 2 (AICPA Trust Services Criteria)",
}

R = Requirement
REQUIREMENTS: tuple[Requirement, ...] = (
    # --- GDPR ---------------------------------------------------------------
    R("gdpr", "Art. 5(1)(c)", "Data minimisation",
      ("detect", "redact-egress", "placeholders"), SUPPORTS,
      "the LLM and outside tools get placeholders or masks instead of the personal data "
      "Taintward finds",
      "only values the detector finds or the placeholder map knows; the meaning of the "
      "text around them still goes out", "raw_check"),
    R("gdpr", "Art. 5(1)(f)", "Integrity and confidentiality",
      ("redact-egress", "vault-encryption", "keys", "telemetry"), SUPPORTS,
      "personal data is kept out of outside calls and telemetry, and originals are "
      "encrypted at rest",
      "the rest of your system (databases, backups, access control) is outside Taintward",
      "raw_check"),
    R("gdpr", "Art. 5(2)", "Accountability (be able to show compliance)",
      ("records", "evidence-log", "report"), PARTLY,
      "a report with the numbers from the recorded calls and a verifiable evidence log",
      "covers the data flows through Taintward, not your other processing", "evidence_log"),
    R("gdpr", "Art. 17", "Right to erasure",
      ("erasure",), PARTLY,
      "a subject's vault rows and a conversation's placeholders can be deleted",
      "data a provider or tool already received is outside Taintward; with the in-memory "
      "vault, digit-only tokens can still be decrypted with the FPE key"),
    R("gdpr", "Art. 25", "Data protection by design and by default",
      ("redact-egress", "placeholders", "destinations"), SUPPORTS,
      "redaction is on by default, placeholders are the default for the LLM, and a tool "
      "nobody mapped is treated as external (masked)",
      "the defaults protect what goes through Taintward; the design of the rest is yours"),
    R("gdpr", "Art. 30", "Records of processing activities",
      ("records", "report"), PARTLY,
      "the report lists which tools and destinations received personal data, by data "
      "class and jurisdiction",
      "the record itself (purposes, legal basis, retention, controller details) is yours",
      "recipients"),
    R("gdpr", "Art. 32(1)(a)", "Pseudonymisation and encryption",
      ("placeholders", "tokens", "vault-encryption", "keys"), SUPPORTS,
      "placeholders and FF1 tokens pseudonymise values; the vault encrypts originals with "
      "keys that can be KMS-wrapped and rotated",
      "pseudonymised data is still personal data; FF1 here is not a validated product"),
    R("gdpr", "Art. 33 and 34", "Personal data breach notification",
      ("records", "evidence-log", "report"), PARTLY,
      "shows which runs, tools and destinations got sensitive data in a window, to scope a "
      "breach",
      "detecting the breach and notifying are yours", "violations"),
    R("gdpr", "Art. 44", "Transfers to third countries",
      ("destinations", "report"), PARTLY,
      "calls to a jurisdiction the policy marks as not adequate are flagged as transfers "
      "and counted per jurisdiction",
      "a flag from your configuration, not a legal assessment; adequacy decisions and "
      "safeguards (Art. 45 and 46) are yours", "transfers"),
    # --- EU AI Act ------------------------------------------------------------
    R("eu-ai-act", "Art. 10", "Data and data governance (training data)",
      (), NOT_COVERED,
      "-",
      "about training, validation and testing data of high-risk systems; Taintward works "
      "at run time"),
    R("eu-ai-act", "Art. 12", "Record-keeping (automatic logs)",
      ("records", "evidence-log"), PARTLY,
      "every tool and model call through Taintward is logged with its decision; violations "
      "go into a tamper-evident log",
      "logs only the calls that go through Taintward; what the system's logs must hold "
      "for its purpose is the provider's to decide", "evidence_log"),
    R("eu-ai-act", "Art. 15", "Accuracy, robustness and cybersecurity",
      ("redact-egress", "placeholders", "gateway"), PARTLY,
      "limits what a prompt injection can leak: tools and the model get placeholders or "
      "masks, links in answers keep their placeholders, the gateway can block calls",
      "does not detect or remove injected instructions, and does nothing for model "
      "accuracy", "violations"),
    R("eu-ai-act", "Art. 26(6)", "Deployers keep logs for at least six months",
      ("records", "evidence-log"), PARTLY,
      "the spans and the evidence log are the logs to keep",
      "retention is set by your trace store and where you keep the evidence log"),
    # --- HIPAA ------------------------------------------------------------------
    R("hipaa", "§164.502(b)", "Minimum necessary",
      ("detect", "redact-egress", "placeholders"), SUPPORTS,
      "the LLM and outside tools get placeholders or masks for the PHI Taintward finds",
      "only the identifiers the detector finds", "raw_check"),
    R("hipaa", "§164.514(b)", "De-identification (Safe Harbor)",
      ("detect",), NOT_COVERED,
      "-",
      "Taintward finds some of the 18 Safe Harbor identifiers (names partly, addresses, "
      "phone, email, SSN, account numbers) but not dates, ages, record or device numbers, "
      "so redacted text is not de-identified"),
    R("hipaa", "§164.312(a)(2)(iv)", "Encryption and decryption",
      ("vault-encryption", "keys"), SUPPORTS,
      "originals in the vault are encrypted with AES-GCM under managed keys",
      "PHI stored elsewhere in your system is outside Taintward"),
    R("hipaa", "§164.312(b)", "Audit controls",
      ("records", "evidence-log", "reversal-audit"), SUPPORTS,
      "calls, policy decisions and every reversal of a token are recorded",
      "only activity that goes through Taintward", "evidence_log"),
    R("hipaa", "§164.312(c)(1)", "Integrity",
      ("evidence-log",), PARTLY,
      "changes to recorded violations are detected by the Merkle log and checkpoints",
      "protects the evidence, not the PHI in your stores"),
    R("hipaa", "§164.312(e)(1)", "Transmission security",
      ("redact-egress", "placeholders"), PARTLY,
      "detected PHI is not in what is sent to the LLM or outside tools",
      "encryption in transit (TLS) is the connection's job"),
    R("hipaa", "§164.308(a)(1)(ii)(D)", "Information system activity review",
      ("report",), SUPPORTS,
      "the report is a periodic review of sensitive data flows and violations",
      "reviewing it and acting on it are yours", "violations"),
    R("hipaa", "§164.308(b)", "Business associate contracts",
      (), NOT_COVERED,
      "-",
      "an LLM provider that receives PHI needs a business associate agreement; Taintward "
      "reduces what it receives but does not replace the agreement"),
    # --- SOC 2 ------------------------------------------------------------------
    R("soc2", "CC6.1", "Logical access security and encryption keys",
      ("vault-encryption", "keys"), SUPPORTS,
      "originals are encrypted, keys can be KMS-wrapped only, rotated on a schedule",
      "user access to your systems is outside Taintward"),
    R("soc2", "CC6.7", "Restricting and protecting transmission of information",
      ("redact-egress", "destinations", "gateway"), SUPPORTS,
      "what each destination gets is set by policy; external and LLM calls get masks or "
      "placeholders; the gateway can block",
      "only transmissions through Taintward", "raw_check"),
    R("soc2", "CC7.2", "Monitoring for anomalies and security events",
      ("records", "destinations"), PARTLY,
      "egress violations and transfers are flagged on every span by the collector policy",
      "alerting on them is set up in your observability tool", "violations"),
    R("soc2", "CC7.3", "Evaluating security events",
      ("report", "evidence-log"), PARTLY,
      "the report lists each violation with its trace, rule and outcome",
      "the incident process is yours", "violations"),
    R("soc2", "C1.1", "Identifying and protecting confidential information",
      ("detect", "redact-egress"), PARTLY,
      "secrets and PII are found and redacted on the way out",
      "detection coverage has limits (docs/benchmark.md)", "raw_check"),
    R("soc2", "C1.2", "Disposing of confidential information",
      ("erasure",), PARTLY,
      "vault rows and placeholders can be erased by subject or conversation",
      "copies outside the vault are yours"),
    R("soc2", "P6.1", "Disclosure of personal information to third parties",
      ("records", "report"), PARTLY,
      "the report shows which third parties received personal data",
      "consent and the disclosure policy are yours", "recipients"),
)
del R


def parse_frameworks(text: str | None) -> tuple[str, ...]:
    """'gdpr,hipaa' or 'all' -> framework ids. Raises ValueError for unknown ones."""
    if not text:
        return ()
    # eu_ai_act is accepted for eu-ai-act
    names = [t.strip().lower().replace("_", "-") for t in text.split(",") if t.strip()]
    if names == ["all"]:
        return tuple(FRAMEWORKS)
    bad = [n for n in names if n not in FRAMEWORKS]
    if bad:
        raise ValueError(f"unknown framework {', '.join(bad)}; use {', '.join(FRAMEWORKS)} or all")
    return tuple(dict.fromkeys(names))


def _evidence(key: str, data: dict) -> str:
    """What this report shows for a requirement, from its own numbers."""
    if key == "raw_check":
        claim = data.get("raw_check", {}).get("claim", {})
        return f"Section 7: {claim.get('statement', 'no raw value check')}"
    if key == "violations":
        v = data.get("violations", {})
        by = ", ".join(f"{k} {n}" for k, n in v.get("by_outcome", {}).items() if n)
        return f"Section 4: {v.get('total', 0)} violation(s)" + (f" ({by})" if by else "")
    if key == "transfers":
        t = data.get("transfers", {})
        by = ", ".join(f"{k}: {v.get('transfer_flags', 0) if isinstance(v, dict) else v}"
                       for k, v in t.get("by_jurisdiction", {}).items())
        return f"Section 5: {t.get('total', 0)} transfer(s)" + (f" ({by})" if by else "")
    if key == "recipients":
        rec = data.get("recipients") or []
        n = sum(1 for r in rec if r.get("sensitive_calls"))
        return f"Section 6: {n} of {len(rec)} recipient(s) received sensitive data"
    if key == "evidence_log":
        ev = data.get("evidence_log")
        if not ev:
            return "Section 8: no evidence log was given for this report"
        ver = ev.get("verification")
        if ver is None:
            # no public key was given (or no checkpoint exists yet): nothing
            # was checked, which is not the same as a failed check
            state = "not verified in this report"
        else:
            state = "verified" if ver.get("ok") else "verification failed"
        n = ev.get("records")
        size = "that could not be read" if n is None else f"with {n} record(s)"
        return f"Section 8: evidence log {size}, {state}"
    return ""


def rows(frameworks: tuple[str, ...], data: dict | None = None) -> list[dict]:
    """The mapping rows for these frameworks, with the report's own evidence."""
    out = []
    for r in REQUIREMENTS:
        if r.framework not in frameworks:
            continue
        out.append({
            "framework": r.framework, "ref": r.ref, "title": r.title, "level": r.level,
            "controls": [CONTROLS[c].name for c in r.controls], "how": r.how,
            "limits": r.limits,
            "evidence": _evidence(r.report, data) if (data is not None and r.report) else "",
        })
    return out


DISCLAIMER = ("This maps what Taintward does to these requirements. It is not legal advice, "
              "and Taintward does not by itself make a system compliant: most requirements "
              "also need things outside it.")


def markdown() -> str:
    """docs/compliance.md."""
    out = ["# Compliance mappings", "",
           "Which Taintward controls support which requirement of GDPR, the EU AI Act, "
           "HIPAA and SOC 2, and where the limits are. " + DISCLAIMER, "",
           "Levels: **supports**: Taintward does the technical part of the requirement for "
           "the data that goes through it. **partly**: it helps (evidence, scoping, one "
           "part). **not covered**: listed so nobody assumes it is.", "",
           "The report can add this table with its own numbers as evidence:", "",
           "```bash",
           "python -m taintward.evidence.report --source jaeger --service my-agent \\",
           "    --since 30d --frameworks gdpr,hipaa --out report.html",
           "```", "",
           "`--frameworks all` adds every framework. This page is generated from "
           "`taintward/evidence/compliance.py` (`python -m taintward.evidence.compliance > "
           "docs/compliance.md`).", "",
           "## Controls", "",
           "| control | what it does | code |", "|---|---|---|"]
    for c in CONTROLS.values():
        out.append(f"| {c.name} | {c.what} | `{c.code}` |")
    for fid, fname in FRAMEWORKS.items():
        out += ["", f"## {fname}", "",
                "| requirement | level | how Taintward helps | controls | limits |",
                "|---|---|---|---|---|"]
        for r in REQUIREMENTS:
            if r.framework != fid:
                continue
            names = ", ".join(CONTROLS[c].name for c in r.controls) or "-"
            out.append(f"| {r.ref} {r.title} | {r.level} | {r.how} | {names} | {r.limits} |")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    sys.stdout.write(markdown())
