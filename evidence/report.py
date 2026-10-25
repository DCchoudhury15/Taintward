"""Sensitive data flow report: a document you can attach for a customer.

It answers "do you send our customers' personal data to LLM providers or
other third parties?" with numbers from the recorded spans, for one time
window:

* how many agent runs and tool calls there were,
* which calls touched sensitive data, by class (pii, secret, ...),
* calls per destination class (internal, llm, external, log, rag),
* policy violations and what happened to each (redacted, blocked, audit only),
* cross-border transfers by jurisdiction (GDPR Art. 44),
* which tools and destinations received data (the GDPR Art. 30 recipients
  view),
* a check of what was actually sent to external and LLM destinations for
  raw sensitive values, with the method and its limits,
* the Merkle evidence log root and signed checkpoint, and how to verify them.

The headline "0 raw sensitive values were sent ..." is printed only when the
data supports it: every external and LLM call has its sent input recorded,
none ran in audit-only mode on sensitive data, the scan found nothing and
the source was not truncated. Otherwise the report says what it could not
confirm and why.

Usage::

    python -m evidence.report --source jaeger --service agentward-hr-bot \\
        --since 24h --out report.html
    python -m evidence.report --source otlp-file --otlp-file traces.json \\
        --format json
    python -m evidence.report --source clickhouse --service my-agent \\
        --since 30d --evidence-dir evidence-log --public-key evidence.pub

Open the HTML file in a browser and use Print, then "Save as PDF".
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from evidence.merkle import LogCorruptError, MerkleLog, violation_record
from evidence.spans import ClickHouseSource, JaegerSource, OtlpFileSource, Span

REPORT_VERSION = 1

DEST_ORDER = ("internal", "llm", "external", "log", "rag")
CLAIM_DESTS = ("external", "llm")          # the headline statement covers these
CHECKED_DESTS = ("llm", "external", "log", "rag")  # raw value scan runs on these
INPUT_ATTRS = ("gen_ai.tool.call.arguments", "gen_ai.input.messages")

OUTCOME_LABELS = {
    "blocked": "Blocked (the call was not made)",
    "audit_only": "Audit only (recorded, data sent unchanged)",
    "redacted": "Redacted before sending",
    "nothing_to_redact": "Sent with no raw value left to redact",
}
OUTCOME_ORDER = ("redacted", "nothing_to_redact", "blocked", "audit_only")

DEST_LABELS = {
    "internal": "Internal systems (own database, own services)",
    "llm": "LLM providers",
    "external": "External APIs and third parties",
    "log": "Logs",
    "rag": "Retrieval / vector store",
    "": "(not set)",
}

# Patterns for the raw value check. They match the collector's redaction
# patterns (collector/processor/taintpolicy/processor.go) plus card numbers
# (Luhn checked) and private key blocks. A mask such as [PII] never matches.
RAW_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("US_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("EMAIL_ADDRESS", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("PHONE_NUMBER", re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _fp(value: str) -> str:
    """Short one-way fingerprint, so a finding can be traced without the value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def scan_text(text: str, *, deep: bool = False) -> list[dict]:
    """Find raw sensitive values in ``text``. Returns types and fingerprints
    only, never the values."""
    found: list[dict] = []
    for kind, rx in RAW_PATTERNS:
        for m in rx.finditer(text):
            if kind == "CREDIT_CARD" and not _luhn_ok(m.group(0)):
                continue
            found.append({"type": kind, "fingerprint": _fp(m.group(0))})
    if deep:
        from sdk.detect import detect_text

        for d in detect_text(text):
            found.append({"type": d.entity_type, "fingerprint": _fp(text[d.start:d.end])})
    # one entry per (type, fingerprint)
    uniq = {(f["type"], f["fingerprint"]): f for f in found}
    return list(uniq.values())


# ---------------------------------------------------------------------------
# span classification
# ---------------------------------------------------------------------------

def _truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def _split(v: Any) -> list[str]:
    if not v:
        return []
    return [x.strip() for x in str(v).split(",") if x.strip()]


def is_tool_call(s: Span) -> bool:
    return "agentward.destination" in s.attrs


def destination(s: Span) -> str:
    return str(s.attrs.get("agentward.destination", "") or "")


def jurisdiction(s: Span) -> str:
    return str(s.attrs.get("agentward.jurisdiction", "") or "")


def tool_name(s: Span) -> str:
    return str(s.attrs.get("gen_ai.tool.name") or s.name)


def is_sensitive(s: Span) -> bool:
    return _truthy(s.attrs.get("agentward.sensitive", False))


def classes(s: Span) -> list[str]:
    return sorted(set(_split(s.attrs.get("agentward.taint.classes"))))


def rules(s: Span) -> list[str]:
    r = _split(s.attrs.get("agentward.policy.reasons")) or _split(s.attrs.get("agentward.policy.rules"))
    if not r and _truthy(s.attrs.get("agentward.violation")):
        r = ["sdk_egress_gate"]
    return sorted(set(r))


def is_violation(s: Span) -> bool:
    a = s.attrs
    return (_truthy(a.get("agentward.policy.violation", False))
            or _truthy(a.get("agentward.violation", False)))


def is_transfer(s: Span) -> bool:
    return (_truthy(s.attrs.get("agentward.policy.transfer_violation", False))
            or "transfer" in rules(s))


def is_audit(s: Span) -> bool:
    return (_truthy(s.attrs.get("agentward.dry_run", False))
            or str(s.attrs.get("agentward.mode", "")) == "audit")


def is_blocked(s: Span) -> bool:
    return _truthy(s.attrs.get("agentward.blocked", False))


def was_redacted(s: Span) -> bool:
    return (_truthy(s.attrs.get("agentward.redacted", False))
            or _truthy(s.attrs.get("agentward.args.redacted", False)))


def outcome(s: Span) -> str:
    """What happened to a call: blocked, audit_only, redacted or
    nothing_to_redact (the gate ran but the input held no raw value, for
    example because an earlier step had already masked it)."""
    if is_blocked(s):
        return "blocked"
    if is_audit(s):
        return "audit_only"
    if was_redacted(s):
        return "redacted"
    return "nothing_to_redact"


def decided_by(s: Span) -> str:
    if s.attrs.get("agentward.policy.decision_engine"):
        return "collector"
    if s.attrs.get("agentward.gateway.upstream") is not None or s.attrs.get("agentward.mode"):
        return "gateway"
    return "sdk"


def sent_input(s: Span) -> str | None:
    """The recorded input of a call, as the sink received it. None when the
    span has no input attribute."""
    for k in INPUT_ATTRS:
        if k in s.attrs:
            v = s.attrs[k]
            return v if isinstance(v, str) else json.dumps(v, default=str)
    return None


def span_violation_record(s: Span) -> dict:
    """The evidence log leaf for a violating span (no raw values)."""
    return violation_record(
        trace_id=s.trace_id, span_id=s.span_id, tool=tool_name(s),
        destination=destination(s), jurisdiction=jurisdiction(s),
        classes=",".join(classes(s)), reasons=",".join(rules(s)),
        timestamp_ns=int(s.start_ns),
    )


# ---------------------------------------------------------------------------
# evidence log section
# ---------------------------------------------------------------------------

def _evidence_section(violations: list[Span], *, evidence_dir: str | None,
                      log_file: str | None, public_key: str | None,
                      start_ns: int = 0, end_ns: int = 0) -> dict | None:
    if not evidence_dir and not log_file:
        return None
    try:
        return _evidence_section_inner(violations, evidence_dir=evidence_dir,
                                       log_file=log_file, public_key=public_key,
                                       start_ns=start_ns, end_ns=end_ns)
    except LogCorruptError as e:
        # a broken log file must show up in the report, not stop it
        return {
            "kind": "sharded" if evidence_dir else "single_file",
            "path": str(evidence_dir or log_file), "records": None, "root": None,
            "violations_in_window": len(violations), "violations_found_in_log": None,
            "violations_covered_by_checkpoint": None, "checkpoint": None,
            "verification": {"ok": False, "errors": [str(e)], "warnings": [],
                             "shards_checked": 0},
            "shards": [],
        }


def _evidence_section_inner(violations: list[Span], *, evidence_dir: str | None,
                            log_file: str | None, public_key: str | None,
                            start_ns: int, end_ns: int) -> dict:
    wanted = {(s.trace_id, s.span_id) for s in violations}
    if log_file:
        log = MerkleLog(log_file)
        present = {(r.get("trace_id"), r.get("span_id")) for r in log.records()}
        return {
            "kind": "single_file",
            "path": str(log_file),
            "records": len(log),
            "root": log.root().hex(),
            "violations_in_window": len(wanted),
            "violations_found_in_log": len(wanted & present),
            "violations_covered_by_checkpoint": None,
            "checkpoint": None,
            "verification": None,
            "shards": [],
        }

    from evidence.checkpoint import body_hash, list_checkpoints, load_checkpoint
    from evidence.shards import ShardedLog

    log = ShardedLog(evidence_dir)
    index: dict[tuple, tuple[str, str, int]] = {}
    for t, d in log.list_shards():
        for i, r in enumerate(log.shard(t, d).records()):
            index[(r.get("trace_id"), r.get("span_id"))] = (t, d, i)
    cps = list_checkpoints(log.checkpoint_dir)
    cp_info = None
    signed_sizes: dict[tuple[str, str], int] = {}
    if cps:
        seq, path = cps[-1]
        body = load_checkpoint(path)["body"]
        cp_info = {
            "seq": body["seq"], "time": body["time"], "hash": body_hash(body),
            "key_id": body["key_id"], "total_records": body["total_records"],
            "file": str(path),
        }
        signed_sizes = {(s["tenant"], s["day"]): int(s["size"]) for s in body["shards"]}
    found = [index[k] for k in wanted if k in index]
    covered = sum(1 for t, d, i in found if i < signed_sizes.get((t, d), 0))
    verification = None
    if public_key and cps:
        from evidence.checkpoint import load_public_key, verify_log

        res = verify_log(evidence_dir, load_public_key(public_key))
        verification = {"ok": res.ok, "errors": res.errors, "warnings": res.warnings,
                        "shards_checked": res.shards_checked}
    from evidence.shards import utc_day

    first, last = utc_day(start_ns), utc_day(max(start_ns, end_ns - 1))
    shards = [h.to_dict() for h in log.heads() if first <= h.day <= last]
    return {
        "kind": "sharded",
        "path": str(evidence_dir),
        "records": sum(h.size for h in log.heads()),
        "root": None,
        "violations_in_window": len(wanted),
        "violations_found_in_log": len(found),
        "violations_covered_by_checkpoint": covered if cps else None,
        "checkpoint": cp_info,
        "verification": verification,
        "shards": shards,
    }


# ---------------------------------------------------------------------------
# building the report data
# ---------------------------------------------------------------------------

def _iso(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_report(spans: Iterable[Span], *, start_ns: int, end_ns: int,
                 source: str, title: str = "Sensitive data flow report",
                 organization: str = "", system: str = "",
                 deep_scan: bool = False, truncated: bool = False,
                 evidence_dir: str | None = None, log_file: str | None = None,
                 public_key: str | None = None, max_rows: int = 500,
                 generated_ns: int | None = None) -> dict:
    """Compute every number in the report. Pure: no network, no clock unless
    ``generated_ns`` is left out."""
    spans = sorted(spans, key=lambda s: (s.start_ns, s.trace_id, s.span_id))
    calls = [s for s in spans if is_tool_call(s)]
    runs = {s.trace_id for s in calls}
    services = sorted({s.service for s in spans if s.service})
    sensitive = [s for s in calls if is_sensitive(s)]
    violations = [s for s in calls if is_violation(s)]

    by_class: Counter = Counter()
    for s in sensitive:
        for c in classes(s) or ["unclassified"]:
            by_class[c] += 1

    dests: dict[str, dict] = {}
    for d in DEST_ORDER:
        dests[d] = {"calls": 0, "sensitive_calls": 0, "violations": 0}
    for s in calls:
        row = dests.setdefault(destination(s), {"calls": 0, "sensitive_calls": 0,
                                                "violations": 0})
        row["calls"] += 1
        row["sensitive_calls"] += is_sensitive(s)
        row["violations"] += is_violation(s)

    v_outcome: Counter = Counter(outcome(s) for s in violations)
    v_rule: Counter = Counter()
    v_dest: Counter = Counter(destination(s) for s in violations)
    for s in violations:
        for r in rules(s) or ["unspecified"]:
            v_rule[r] += 1

    # cross-border view: every call with a jurisdiction set
    juris: dict[str, dict] = {}
    for s in calls:
        j = jurisdiction(s)
        if not j:
            continue
        row = juris.setdefault(j, {"calls": 0, "pii_calls": 0, "transfer_flags": 0,
                                   "outcomes": Counter()})
        row["calls"] += 1
        row["pii_calls"] += "pii" in classes(s)
        if is_transfer(s):
            row["transfer_flags"] += 1
            row["outcomes"][outcome(s)] += 1
    for row in juris.values():
        row["outcomes"] = dict(row["outcomes"])
    transfers = [s for s in calls if is_transfer(s)]

    # Art. 30 recipients view
    rec: dict[tuple, dict] = {}
    for s in calls:
        k = (tool_name(s), destination(s), jurisdiction(s))
        row = rec.setdefault(k, {"tool": k[0], "destination": k[1], "jurisdiction": k[2],
                                 "calls": 0, "sensitive_calls": 0, "classes": set(),
                                 "violations": 0, "outcomes": Counter()})
        row["calls"] += 1
        if is_sensitive(s):
            row["sensitive_calls"] += 1
            row["classes"].update(classes(s))
        if is_violation(s):
            row["violations"] += 1
            row["outcomes"][outcome(s)] += 1
    dest_rank = {d: i for i, d in enumerate(DEST_ORDER)}
    recipients = []
    for row in sorted(rec.values(), key=lambda r: (dest_rank.get(r["destination"], 99),
                                                   r["tool"], r["jurisdiction"])):
        row["classes"] = sorted(row["classes"])
        row["outcomes"] = dict(row["outcomes"])
        recipients.append(row)

    # raw value check on what was sent out
    raw_by_dest: dict[str, dict] = {}
    findings: list[dict] = []
    for d in CHECKED_DESTS:
        raw_by_dest[d] = {"calls": 0, "measured": 0, "not_measured": 0, "blocked": 0,
                          "audit_only_sensitive": 0, "calls_with_raw": 0, "raw_values": 0}
    for s in calls:
        d = destination(s)
        if d not in raw_by_dest:
            continue
        row = raw_by_dest[d]
        row["calls"] += 1
        if is_blocked(s):
            row["blocked"] += 1  # nothing left the system
            continue
        if is_audit(s) and is_sensitive(s):
            row["audit_only_sensitive"] += 1
        text = sent_input(s)
        if text is None:
            row["not_measured"] += 1
            continue
        row["measured"] += 1
        hits = scan_text(text, deep=deep_scan)
        if hits:
            row["calls_with_raw"] += 1
            row["raw_values"] += len(hits)
            findings.append({
                "time": _iso(s.start_ns), "trace_id": s.trace_id, "span_id": s.span_id,
                "tool": tool_name(s), "destination": d, "jurisdiction": jurisdiction(s),
                "types": sorted({h["type"] for h in hits}),
                "fingerprints": sorted({h["fingerprint"] for h in hits}),
                "outcome": outcome(s),
            })

    policy_errors = sum(1 for s in calls if s.attrs.get("agentward.policy.error"))
    claim = _claim(raw_by_dest, truncated=truncated, policy_errors=policy_errors)

    decided = Counter(decided_by(s) for s in calls)
    warnings: list[str] = []
    if truncated:
        warnings.append("The trace source returned its maximum number of traces for at "
                        "least one one-second slice, so some spans may be missing.")
    if policy_errors:
        warnings.append(f"{policy_errors} call(s) have a policy evaluation error "
                        f"(agentward.policy.error); the policy did not decide on them.")
    if calls and not decided.get("collector"):
        warnings.append("No span carries a collector policy decision. The numbers come from "
                        "the SDK or gateway flags only; the AgentWard collector did not "
                        "process these spans.")
    if not calls:
        warnings.append("No AgentWard tool call spans were found in this window.")

    evidence = _evidence_section(violations, evidence_dir=evidence_dir, log_file=log_file,
                                 public_key=public_key, start_ns=start_ns, end_ns=end_ns)

    vlist = [{
        "time": _iso(s.start_ns), "trace_id": s.trace_id, "span_id": s.span_id,
        "tool": tool_name(s), "destination": destination(s),
        "jurisdiction": jurisdiction(s), "classes": classes(s), "rules": rules(s),
        "outcome": outcome(s), "decided_by": decided_by(s),
    } for s in violations]

    data = {
        "report_version": REPORT_VERSION,
        "title": title,
        "organization": organization,
        "system": system,
        "generated_at": _iso(generated_ns if generated_ns is not None else time.time_ns()),
        "window": {"start": _iso(start_ns), "end": _iso(end_ns),
                   "start_ns": start_ns, "end_ns": end_ns},
        "source": source,
        "services": services,
        "totals": {
            "spans": len(spans),
            "runs": len(runs),
            "tool_calls": len(calls),
            "sensitive_calls": len(sensitive),
            "violations": len(violations),
            "transfers": len(transfers),
        },
        "sensitive_by_class": dict(sorted(by_class.items())),
        "destinations": dests,
        "violations": {
            "total": len(violations),
            "by_outcome": {k: v_outcome.get(k, 0) for k in OUTCOME_ORDER},
            "by_rule": dict(sorted(v_rule.items())),
            "by_destination": dict(sorted(v_dest.items())),
        },
        "transfers": {"total": len(transfers), "by_jurisdiction": dict(sorted(juris.items()))},
        "recipients": recipients,
        "raw_check": {
            "method": ("Every call to an llm, external, log or rag destination was checked. "
                       "The recorded input of the call (gen_ai.tool.call.arguments or "
                       "gen_ai.input.messages) was scanned for raw values with these "
                       "patterns: " + ", ".join(k for k, _ in RAW_PATTERNS)
                       + (", plus the full Presidio detector set" if deep_scan else "")
                       + ". Masks such as [PII] do not match."),
            "patterns": [k for k, _ in RAW_PATTERNS],
            "deep_scan": deep_scan,
            "by_destination": raw_by_dest,
            "findings": findings,
            "claim": claim,
        },
        "decided_by": dict(sorted(decided.items())),
        "evidence_log": evidence,
        "violation_list": vlist[:max_rows],
        "violation_list_truncated": len(vlist) > max_rows,
        "warnings": warnings,
        "limits": LIMITS + ([] if deep_scan else [DEEP_SCAN_LIMIT]),
    }
    data["digest"] = hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return data


DEEP_SCAN_LIMIT = (
    "The raw value check uses fixed patterns (SSN, AWS key, GitHub token, email, phone, "
    "card number, private key). Names, addresses and free text personal data are not "
    "matched by these patterns. Run with --deep-scan to also use the Presidio detectors "
    "(slower, more false positives)."
)

LIMITS = [
    "The report covers only calls made through AgentWard (SDK wrappers, framework "
    "adapters or the MCP gateway). Calls that bypass it are not recorded and not counted.",
    "Sensitivity comes from AgentWard's detectors (Presidio and secret patterns) plus the "
    "taint carried along each run. A value the detectors do not recognize is not counted "
    "as sensitive.",
    "The raw value check reads the input as recorded on the span. For SDK calls this is "
    "the input after the redaction gate, the same value the destination received. For the "
    "MCP gateway, arguments listed in passthrough_args are forwarded unchanged but stored "
    "masked on the span, so they cannot be checked here; review that list separately.",
    "Calls in audit-only mode forward data without redaction. When such a call carried "
    "sensitive data, the report does not make the \"0 raw values\" statement.",
    "The numbers are only as complete as the trace store. Sampling, retention limits or "
    "dropped spans reduce what is counted. The evidence log and its signed checkpoints "
    "show that recorded violations were not changed or removed later; they do not prove "
    "that every call was recorded.",
    "Jurisdictions come from the destination configuration (agentward.jurisdiction). "
    "A transfer flag means the policy marked that jurisdiction as not adequate for "
    "personal data and the call was part of a run that had touched personal data. It does "
    "not by itself mean raw personal data was sent; see the raw value check.",
]


def _claim(raw_by_dest: dict, *, truncated: bool, policy_errors: int) -> dict:
    calls = sum(raw_by_dest[d]["calls"] for d in CLAIM_DESTS)
    raw = sum(raw_by_dest[d]["raw_values"] for d in CLAIM_DESTS)
    raw_calls = sum(raw_by_dest[d]["calls_with_raw"] for d in CLAIM_DESTS)
    unmeasured = sum(raw_by_dest[d]["not_measured"] for d in CLAIM_DESTS)
    audit = sum(raw_by_dest[d]["audit_only_sensitive"] for d in CLAIM_DESTS)
    measured = sum(raw_by_dest[d]["measured"] for d in CLAIM_DESTS)
    blocked = sum(raw_by_dest[d]["blocked"] for d in CLAIM_DESTS)
    if raw:
        return {"status": "raw_found",
                "statement": (f"{raw} raw sensitive value(s) were found in data sent to "
                              f"external or LLM destinations, in {raw_calls} call(s). "
                              f"See the findings table."),
                "reasons": []}
    reasons = []
    if unmeasured:
        reasons.append(f"{unmeasured} external or LLM call(s) have no recorded input, so "
                       f"what they sent could not be checked.")
    if audit:
        reasons.append(f"{audit} external or LLM call(s) ran in audit-only mode on a run "
                       f"that held sensitive data; audit mode sends data without redaction.")
    if truncated:
        reasons.append("The trace source may have returned fewer spans than exist.")
    if policy_errors:
        reasons.append(f"{policy_errors} call(s) had a policy evaluation error.")
    if calls == 0:
        return {"status": "no_calls",
                "statement": "No calls to external or LLM destinations were recorded in "
                             "this period.",
                "reasons": reasons}
    if reasons:
        return {"status": "not_confirmed",
                "statement": "It could not be confirmed that no raw sensitive values were "
                             "sent to external or LLM destinations in this period.",
                "reasons": reasons}
    extra = f", {blocked} more were blocked before sending" if blocked else ""
    return {"status": "supported",
            "statement": (f"0 raw sensitive values were sent to external or LLM destinations "
                          f"in this period ({measured} call(s) checked{extra})."),
            "reasons": []}


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
:root { color-scheme: light; --ink:#1d2329; --muted:#5b6670; --line:#d5dbe0;
  --soft:#f4f6f8; --ok:#1f6b3a; --ok-bg:#eaf5ee; --warn:#7a5300; --warn-bg:#fdf5e3;
  --bad:#8a1c1c; --bad-bg:#fbeaea; }
* { box-sizing: border-box; }
html { background:#fff; }
body { margin:0; background:#fff; color:var(--ink);
  font: 14px/1.5 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 32px 16px 48px; }
header { border-bottom: 2px solid var(--ink); padding-bottom: 12px; margin-bottom: 20px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 28px 0 6px; padding-bottom: 4px;
  border-bottom: 1px solid var(--line); break-after: avoid; }
h3 { font-size: 14px; margin: 16px 0 4px; }
p { margin: 6px 0; }
.meta { color: var(--muted); margin: 2px 0; }
.meta b { color: var(--ink); font-weight: 600; }
.explain { color: var(--muted); margin: 0 0 8px; }
.statement { border: 1px solid; border-left-width: 6px; padding: 12px 14px;
  margin: 12px 0; break-inside: avoid; }
.statement p.main { font-size: 16px; font-weight: 600; margin: 0 0 4px; }
.statement.supported, .statement.no_calls { border-color: var(--ok); background: var(--ok-bg); }
.statement.not_confirmed { border-color: var(--warn); background: var(--warn-bg); }
.statement.raw_found { border-color: var(--bad); background: var(--bad-bg); }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 8px; margin: 12px 0; }
.kpi { border: 1px solid var(--line); padding: 8px 10px; background: var(--soft);
  break-inside: avoid; }
.kpi .n { font-size: 22px; font-weight: 650; font-variant-numeric: tabular-nums; }
.kpi .l { color: var(--muted); font-size: 12px; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 10px; font-size: 13px; }
th, td { border: 1px solid var(--line); padding: 5px 8px; text-align: left;
  vertical-align: top; }
th { background: var(--soft); font-weight: 600; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; overflow-wrap: anywhere; }
pre { background: var(--soft); border: 1px solid var(--line); padding: 8px 10px;
  white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; }
ul { margin: 6px 0; padding-left: 20px; }
.badge { display: inline-block; padding: 0 6px; border: 1px solid var(--line);
  font-size: 12px; white-space: nowrap; }
.ok { color: var(--ok); } .bad { color: var(--bad); } .warn { color: var(--warn); }
footer { margin-top: 32px; padding-top: 8px; border-top: 1px solid var(--line);
  color: var(--muted); font-size: 12px; }
@page { size: A4; margin: 16mm 14mm; }
@media print {
  main { max-width: none; padding: 0; }
  body { font-size: 11pt; }
  .table-wrap { overflow: visible; }
  a { color: inherit; text-decoration: none; }
  h2 { page-break-after: avoid; }
}
"""


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _n(v: int | None) -> str:
    return "n/a" if v is None else f"{v:,}"


def _table(headers: list[str], rows: list[list[Any]], numeric: set[int] = frozenset(),
           empty: str = "None.") -> str:
    if not rows:
        return f"<p class='explain'>{_e(empty)}</p>"
    th = "".join(f"<th class='n'>{_e(h)}</th>" if i in numeric else f"<th>{_e(h)}</th>"
                 for i, h in enumerate(headers))
    body = []
    for r in rows:
        tds = []
        for i, c in enumerate(r):
            cls = " class='n'" if i in numeric else ""
            cell = _n(c) if (i in numeric and isinstance(c, int)) else c
            tds.append(f"<td{cls}>{cell if isinstance(cell, _Raw) else _e(cell)}</td>")
        body.append("<tr>" + "".join(tds) + "</tr>")
    return (f"<div class='table-wrap'><table><thead><tr>{th}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table></div>")


class _Raw(str):
    """Already-escaped HTML for a table cell."""


def _outcomes_text(d: dict) -> str:
    parts = [f"{OUTCOME_LABELS.get(k, k).split(' (')[0].lower()}: {v}"
             for k, v in d.items() if v]
    return ", ".join(parts) if parts else ""


def render_html(data: dict) -> str:
    t = data["totals"]
    claim = data["raw_check"]["claim"]
    out: list[str] = []
    w = out.append
    w("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    w("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    w(f"<title>{_e(data['title'])}</title><style>{_CSS}</style></head><body><main>")

    # header
    w("<header>")
    w(f"<h1>{_e(data['title'])}</h1>")
    if data.get("organization"):
        w(f"<p class='meta'><b>Organization:</b> {_e(data['organization'])}</p>")
    system = data.get("system") or ", ".join(data["services"]) or "n/a"
    w(f"<p class='meta'><b>System:</b> {_e(system)}</p>")
    w(f"<p class='meta'><b>Period:</b> {_e(data['window']['start'])} to "
      f"{_e(data['window']['end'])}</p>")
    w(f"<p class='meta'><b>Generated:</b> {_e(data['generated_at'])} by AgentWard "
      f"evidence report v{data['report_version']}</p>")
    w(f"<p class='meta'><b>Data source:</b> {_e(data['source'])}</p>")
    w("</header>")

    # 1. summary
    w("<h2>1. Summary</h2>")
    w(f"<div class='statement {_e(claim['status'])}'><p class='main'>"
      f"{_e(claim['statement'])}</p>")
    if claim["reasons"]:
        w("<ul>" + "".join(f"<li>{_e(r)}</li>" for r in claim["reasons"]) + "</ul>")
    w("<p>How this was measured and what it does not cover: see sections 7 and 9.</p></div>")
    w("<div class='kpis'>")
    for label, val in (("Agent runs", t["runs"]), ("Tool and model calls", t["tool_calls"]),
                       ("Calls with sensitive data", t["sensitive_calls"]),
                       ("Policy violations", t["violations"]),
                       ("Cross-border flags", t["transfers"])):
        w(f"<div class='kpi'><div class='n'>{_n(val)}</div><div class='l'>{_e(label)}</div></div>")
    w("</div>")
    if data["warnings"]:
        w("<h3>Notes on this data</h3><ul>"
          + "".join(f"<li>{_e(x)}</li>" for x in data["warnings"]) + "</ul>")

    # 2. sensitive data by class
    w("<h2>2. Calls that touched sensitive data</h2>")
    w("<p class='explain'>A call counts here when AgentWard found sensitive data in its "
      "input or output, or when it ran later in a run that had already touched sensitive "
      "data. One call can carry more than one class.</p>")
    w(_table(["Class", "Calls"], [[k, v] for k, v in data["sensitive_by_class"].items()],
             {1}, "No call touched sensitive data."))

    # 3. destinations
    w("<h2>3. Calls by destination</h2>")
    w("<p class='explain'>Each tool is configured with a destination class. Internal means "
      "systems you run; llm, external, log and rag mean the data leaves that boundary or "
      "is stored where it is hard to remove.</p>")
    rows = [[_Raw(f"<b>{_e(d or '(not set)')}</b>: {_e(DEST_LABELS.get(d, 'other'))}"),
             r["calls"], r["sensitive_calls"], r["violations"]]
            for d, r in data["destinations"].items()]
    w(_table(["Destination", "Calls", "With sensitive data", "Violations"], rows, {1, 2, 3}))

    # 4. violations
    v = data["violations"]
    w("<h2>4. Policy violations and what happened to them</h2>")
    w("<p class='explain'>A violation is a call where the policy says sensitive data must "
      "not reach that destination as is. The outcome shows what AgentWard did.</p>")
    w(_table(["Outcome", "Violations"],
             [[OUTCOME_LABELS[k], v["by_outcome"].get(k, 0)] for k in OUTCOME_ORDER],
             {1}))
    if v["by_rule"]:
        w("<h3>By policy rule</h3>")
        w(_table(["Rule", "Count"], [[k, c] for k, c in v["by_rule"].items()], {1}))
    w("<p class='explain'>Rules: <code>pii_egress</code> = sensitive data reaching an "
      "external, llm or log destination; <code>transfer</code> = personal data going to a "
      "jurisdiction the policy marks as not adequate (GDPR Art. 44); "
      "<code>sdk_egress_gate</code> = flagged by the SDK when no collector decision was "
      "recorded.</p>")
    if data["decided_by"]:
        w("<p class='explain'>Who made the decision: " + _e(", ".join(
            f"{k}: {c}" for k, c in data["decided_by"].items())) + " call(s).</p>")

    # 5. transfers
    w("<h2>5. Cross-border transfers (GDPR Art. 44)</h2>")
    w("<p class='explain'>Calls whose destination is in another jurisdiction, grouped by "
      "jurisdiction. A transfer flag is raised by the policy for personal data going to a "
      "jurisdiction it does not treat as adequate.</p>")
    rows = [[j, r["calls"], r["pii_calls"], r["transfer_flags"], _outcomes_text(r["outcomes"])]
            for j, r in data["transfers"]["by_jurisdiction"].items()]
    w(_table(["Jurisdiction", "Calls", "With personal data", "Transfer flags",
              "Outcome of flagged calls"], rows, {1, 2, 3},
             "No call had a jurisdiction configured."))

    # 6. recipients
    w("<h2>6. Recipients of data (GDPR Art. 30)</h2>")
    w("<p class='explain'>Every tool that received data in this period, with its "
      "destination class and jurisdiction. This is the list of recipients for a record "
      "of processing activities, taken from what actually ran.</p>")
    rows = [[_Raw(f"<code>{_e(r['tool'])}</code>"), r["destination"] or "(not set)",
             r["jurisdiction"] or "-", r["calls"], r["sensitive_calls"],
             ", ".join(r["classes"]) or "-", r["violations"], _outcomes_text(r["outcomes"])]
            for r in data["recipients"]]
    w(_table(["Tool", "Destination", "Jurisdiction", "Calls", "With sensitive data",
              "Classes", "Violations", "Outcome"], rows, {3, 4, 6}, "No calls recorded."))

    # 7. raw value check
    rc = data["raw_check"]
    w("<h2>7. Raw value check on data sent out</h2>")
    w(f"<p>{_e(rc['method'])}</p>")
    rows = [[d, r["calls"], r["measured"], r["not_measured"], r["blocked"],
             r["audit_only_sensitive"], r["calls_with_raw"], r["raw_values"]]
            for d, r in rc["by_destination"].items()]
    w(_table(["Destination", "Calls", "Input checked", "Input not recorded", "Blocked",
              "Audit only, sensitive", "Calls with raw values", "Raw values found"],
             rows, {1, 2, 3, 4, 5, 6, 7}))
    if rc["findings"]:
        w("<h3>Findings</h3><p class='explain'>Values are never shown. The fingerprint is "
          "the first 8 hex characters of SHA-256 of the value, so the same value can be "
          "matched across calls.</p>")
        rows = [[f["time"], _Raw(f"<code>{_e(f['tool'])}</code>"), f["destination"],
                 ", ".join(f["types"]), _Raw(f"<code>{_e(', '.join(f['fingerprints']))}</code>"),
                 _Raw(f"<code>{_e(f['trace_id'])}</code>")]
                for f in rc["findings"][:500]]
        w(_table(["Time", "Tool", "Destination", "Types", "Fingerprints", "Trace"], rows))
    else:
        w("<p class='explain'>No raw values were found in the checked inputs.</p>")

    # 8. evidence log
    w("<h2>8. Tamper-evident evidence log</h2>")
    ev = data["evidence_log"]
    if ev is None:
        w("<p>No evidence log was given for this report, so the violations above are not "
          "yet backed by the Merkle log. Record them with <code>agentward-evidence record</code> "
          "and generate the report with <code>--evidence-dir</code>.</p>")
    else:
        w("<p class='explain'>Each violation is stored as a leaf in an append-only Merkle "
          "log (SHA-256). Changing, removing or reordering any record changes the root. "
          "Signed checkpoints fix the roots at a point in time with an Ed25519 key.</p>")
        rows = [["Log location", ev["path"]], ["Records in the log", _n(ev["records"])],
                ["Violations in this period", _n(ev["violations_in_window"])],
                ["Of these, found in the log", _n(ev["violations_found_in_log"])]]
        if ev["kind"] == "sharded":
            rows.append(["Of these, covered by a signed checkpoint",
                         _n(ev["violations_covered_by_checkpoint"])])
        if ev.get("root"):
            rows.append(["Merkle root", _Raw(f"<code>{_e(ev['root'])}</code>")])
        cp = ev.get("checkpoint")
        if cp:
            rows += [["Newest checkpoint", f"#{cp['seq']} at {cp['time']}"],
                     ["Checkpoint hash", _Raw(f"<code>{_e(cp['hash'])}</code>")],
                     ["Signing key id", _Raw(f"<code>{_e(cp['key_id'])}</code>")]]
        elif ev["kind"] == "sharded":
            rows.append(["Newest checkpoint", "none yet"])
        ver = ev.get("verification")
        if ver is not None:
            status = ("<span class='ok'>passed</span>" if ver["ok"]
                      else "<span class='bad'>FAILED</span>")
            rows.append(["Verification when this report was made",
                         _Raw(f"{status} ({ver['shards_checked']} shard(s) checked)")])
        if ev["kind"] == "single_file" and ev.get("records") is not None:
            rows.append(["Tree size for this root", _n(ev["records"])])
        w(_table(["Item", "Value"], rows))
        if ver is not None and ver["errors"]:
            w("<ul>" + "".join(f"<li class='bad'>{_e(x)}</li>" for x in ver["errors"]) + "</ul>")
        if ev["shards"]:
            w("<h3>Shards for the days in this report</h3>")
            w(_table(["Tenant", "Day (UTC)", "Records", "Root"],
                     [[s["tenant"], s["day"], s["size"],
                       _Raw(f"<code>{_e(s['root'])}</code>")] for s in ev["shards"]], {2}))
        w("<h3>How to verify</h3>")
        if ev["kind"] == "sharded":
            w("<pre>agentward-evidence verify-checkpoints --evidence-dir &lt;dir&gt; "
              "--public-key evidence.pub"
              + (f" \\\n    --expect-head {_e(cp['hash'])}" if cp else "")
              + "\n\n# one record, with only the proof file, the checkpoint and the key:\n"
              "agentward-evidence prove-shard --evidence-dir &lt;dir&gt; --tenant &lt;t&gt; "
              "--day &lt;YYYY-MM-DD&gt; --index &lt;i&gt; &gt; proof.json\n"
              "agentward-evidence verify-proof proof.json --public-key evidence.pub</pre>")
        else:
            size = ev["records"] if ev.get("records") is not None else "&lt;n&gt;"
            w("<pre>agentward-evidence --log-file &lt;file&gt; root --size "
              f"{size}   # must print the root above\n"
              f"agentward-evidence --log-file &lt;file&gt; prove &lt;index&gt; --size {size}"
              "\n\n# later: show the log still starts with these records, unchanged\n"
              f"agentward-evidence --log-file &lt;file&gt; consistency --old-size {size} "
              "--old-root &lt;root above&gt;</pre>")
        w("<p class='explain'>Ask the operator for the public key through a separate "
          "channel, not together with this report.</p>")

    # 9. method and limits
    w("<h2>9. Method and limits</h2>")
    w("<p>How the data is produced: each tool call made through AgentWard is recorded as an "
      "OpenTelemetry span. The SDK or gateway detects sensitive data, carries a taint label "
      "along the run, and redacts the input before it reaches an outside destination. The "
      "AgentWard collector evaluates a Rego policy on every span and records the decision "
      "(<code>agentward.policy.*</code>). This report reads those spans back and counts "
      "them. It does not call any LLM.</p>")
    w("<p>What this report does not show:</p><ul>"
      + "".join(f"<li>{_e(x)}</li>" for x in data["limits"]) + "</ul>")

    # 10. violation list
    w("<h2>10. List of violations</h2>")
    rows = [[x["time"], _Raw(f"<code>{_e(x['tool'])}</code>"), x["destination"],
             x["jurisdiction"] or "-", ", ".join(x["classes"]), ", ".join(x["rules"]),
             OUTCOME_LABELS[x["outcome"]].split(" (")[0],
             _Raw(f"<code>{_e(x['trace_id'])}</code>")]
            for x in data["violation_list"]]
    w(_table(["Time", "Tool", "Destination", "Jurisdiction", "Classes", "Rules", "Outcome",
              "Trace"], rows, empty="No violations in this period."))
    if data["violation_list_truncated"]:
        w("<p class='explain'>The list is cut short. Use the JSON output for every row.</p>")

    w("<footer>")
    w(f"<p>Report data digest: <code>{_e(data['digest'])}</code>. This is the SHA-256 of "
      "the report data embedded in this file (element <code>agentward-report-data</code>, "
      "canonical JSON without the <code>digest</code> field), so the numbers can be "
      "checked by a script.</p>")
    w("<p>To save as PDF: open this file in a browser, choose Print, then Save as PDF.</p>")
    w("</footer></main>")
    blob = json.dumps(data, sort_keys=True).replace("</", "<\\/")
    w(f"<script type='application/json' id='agentward-report-data'>{blob}</script>")
    w("</body></html>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_DUR_RE = re.compile(r"^(\d+)\s*([smhdw])$")


def parse_duration(s: str) -> timedelta:
    m = _DUR_RE.match(s.strip())
    if not m:
        raise argparse.ArgumentTypeError(f"bad duration {s!r} (use e.g. 30m, 24h, 7d)")
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days",
                         "w": "weeks"}[unit]: n})


def parse_time(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def window_from_args(args) -> tuple[int, int]:
    end = parse_time(args.end) if args.end else datetime.now(timezone.utc)
    start = parse_time(args.start) if args.start else end - parse_duration(args.since)
    if start >= end:
        raise SystemExit("the start of the window must be before the end")
    return int(start.timestamp() * 1e9), int(end.timestamp() * 1e9)


def add_source_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("data source")
    g.add_argument("--source", choices=("jaeger", "otlp-file", "clickhouse"), default="jaeger")
    g.add_argument("--service", action="append", default=[],
                   help="service name; repeat for several (required for jaeger)")
    g.add_argument("--jaeger-url", default="http://localhost:16686")
    g.add_argument("--jaeger-search-depth", type=int, default=1000)
    g.add_argument("--otlp-file", action="append", default=[],
                   help="OTLP JSON lines file or directory; repeat for several")
    g.add_argument("--clickhouse-url", default=None,
                   help="ClickHouse HTTP URL; default is docker exec into --clickhouse-container")
    g.add_argument("--clickhouse-container", default="signoz-telemetrystore-clickhouse-0-0")
    g.add_argument("--clickhouse-user", default=None)
    g.add_argument("--clickhouse-password", default=None)
    w = ap.add_argument_group("time window (UTC)")
    w.add_argument("--since", default="24h", help="window length ending now (default 24h)")
    w.add_argument("--start", default=None, help="ISO 8601 start, e.g. 2026-10-01T00:00:00Z")
    w.add_argument("--end", default=None, help="ISO 8601 end (default now)")


def source_from_args(args):
    if args.source == "jaeger":
        return JaegerSource(args.jaeger_url, args.service or ["agentward-hr-bot"],
                            search_depth=args.jaeger_search_depth)
    if args.source == "otlp-file":
        if not args.otlp_file:
            raise SystemExit("--otlp-file is required with --source otlp-file")
        return OtlpFileSource(args.otlp_file, services=args.service)
    return ClickHouseSource(args.service, container=args.clickhouse_container,
                            http_url=args.clickhouse_url, user=args.clickhouse_user,
                            password=args.clickhouse_password)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agentward-report",
        description="Sensitive data flow report (HTML or JSON) from AgentWard spans.")
    add_source_args(ap)
    o = ap.add_argument_group("output")
    o.add_argument("--format", choices=("html", "json"), default="html")
    o.add_argument("--out", default="-", help="output file (default stdout)")
    o.add_argument("--title", default="Sensitive data flow report")
    o.add_argument("--org", default="", help="organization name for the header")
    o.add_argument("--system", default="", help="system name (default: service names)")
    o.add_argument("--deep-scan", action="store_true",
                   help="also scan sent inputs with the Presidio detectors (needs spaCy model)")
    o.add_argument("--max-rows", type=int, default=500)
    e = ap.add_argument_group("evidence log")
    e.add_argument("--evidence-dir", default=None, help="sharded evidence log directory")
    e.add_argument("--log-file", default=None, help="single-file evidence log")
    e.add_argument("--public-key", default=None,
                   help="verify the evidence log checkpoints with this public key")
    args = ap.parse_args(argv)

    start_ns, end_ns = window_from_args(args)
    src = source_from_args(args)
    spans = src.fetch(start_ns, end_ns)
    data = build_report(
        spans, start_ns=start_ns, end_ns=end_ns, source=src.describe(), title=args.title,
        organization=args.org, system=args.system, deep_scan=args.deep_scan,
        truncated=bool(getattr(src, "truncated", False)), evidence_dir=args.evidence_dir,
        log_file=args.log_file, public_key=args.public_key, max_rows=args.max_rows,
    )
    text = (json.dumps(data, indent=2, sort_keys=True) if args.format == "json"
            else render_html(data))
    if args.out == "-":
        sys.stdout.write(text + "\n")
    else:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        claim = data["raw_check"]["claim"]
        print(f"wrote {args.out}: {data['totals']['tool_calls']} calls, "
              f"{data['totals']['violations']} violations; {claim['status']}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
