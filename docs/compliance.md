# Compliance mappings

Which Taintward controls support which requirement of GDPR, the EU AI Act, HIPAA and SOC 2, and where the limits are. This maps what Taintward does to these requirements. It is not legal advice, and Taintward does not by itself make a system compliant: most requirements also need things outside it.

Levels: **supports**: Taintward does the technical part of the requirement for the data that goes through it. **partly**: it helps (evidence, scoping, one part). **not covered**: listed so nobody assumes it is.

The report can add this table with its own numbers as evidence:

```bash
python -m taintward.evidence.report --source jaeger --service my-agent \
    --since 30d --frameworks gdpr,hipaa --out report.html
```

`--frameworks all` adds every framework. This page is generated from `taintward/evidence/compliance.py` (`python -m taintward.evidence.compliance > docs/compliance.md`).

## Controls

| control | what it does | code |
|---|---|---|
| Sensitive data detection | finds PII and secrets in tool and model inputs and outputs (patterns with checksums, context rules, spaCy NER) and carries a taint label along the run | `taintward/sdk/detect.py, taintward/sdk/taint.py` |
| Redaction before data leaves | redacts each call's input for its destination before the call runs: one-way masks for external, log and rag sinks | `taintward/sdk/instrumentation.py, taintward/sdk/redact.py` |
| Placeholders for the LLM | the model gets <PERSON_1> style placeholders instead of values; the answer is restored for the caller, never for links in it | `taintward/sdk/placeholders.py` |
| Reversible tokens for internal sinks | internal stores get format-preserving FF1 tokens; the original is kept in the vault | `taintward/sdk/ff1.py, taintward/sdk/redact.py` |
| Originals encrypted at rest | vault rows are sealed with AES-GCM, the token as associated data; subjects are indexed with an HMAC blind index | `taintward/sdk/vault.py` |
| Key management | key rings with KMS-wrapped keys (AWS KMS, Google Cloud KMS, Vault Transit), KMS-only mode, scheduled rotation and reseal | `taintward/sdk/keys.py, deploy/helm/taintward/templates/key-rotation.yaml` |
| Erasure by subject | deletes every vault row of a subject (all key generations) and a conversation's placeholders | `taintward/sdk/vault.py (forget_subject), taintward/sdk/placeholders.py` |
| Destination and jurisdiction policy | each tool has a destination class and jurisdiction; unmapped tools are external; a Rego policy flags egress and cross-border transfers | `taintward/sdk/integrations/__init__.py, collector/policy/pii_egress.rego` |
| MCP gateway | redacts or blocks MCP tool calls after a session has seen sensitive data; pins tool definitions | `taintward/gateway/` |
| Masked telemetry | span inputs and outputs are stored masked; the collector scrubs regex types and drops framework attributes that hold real values | `taintward/sdk/instrumentation.py, collector/processor/taintpolicy/` |
| Per-call records | every wrapped tool and model call is an OpenTelemetry span with its destination, taint, decision and outcome | `taintward/sdk/instrumentation.py` |
| Tamper-evident evidence log | violations go into a Merkle log with signed checkpoints, so a record that is changed or removed later is detected | `taintward/evidence/merkle.py, taintward/evidence/checkpoint.py` |
| Audit of every reversal | each token reversal and placeholder restore by code is recorded (span event and taintward.audit log), with the key id and the caller, never the value | `taintward/sdk/redact.py (record_reversal)` |
| Sensitive data flow report | counts calls, sensitive calls, destinations, violations, transfers and recipients for a time window, checks what was sent for raw values, and verifies the evidence log | `taintward/evidence/report.py` |

## GDPR (Regulation (EU) 2016/679)

| requirement | level | how Taintward helps | controls | limits |
|---|---|---|---|---|
| Art. 5(1)(c) Data minimisation | supports | the LLM and outside tools get placeholders or masks instead of the personal data Taintward finds | Sensitive data detection, Redaction before data leaves, Placeholders for the LLM | only values the detector finds or the placeholder map knows; the meaning of the text around them still goes out |
| Art. 5(1)(f) Integrity and confidentiality | supports | personal data is kept out of outside calls and telemetry, and originals are encrypted at rest | Redaction before data leaves, Originals encrypted at rest, Key management, Masked telemetry | the rest of your system (databases, backups, access control) is outside Taintward |
| Art. 5(2) Accountability (be able to show compliance) | partly | a report with the numbers from the recorded calls and a verifiable evidence log | Per-call records, Tamper-evident evidence log, Sensitive data flow report | covers the data flows through Taintward, not your other processing |
| Art. 17 Right to erasure | partly | a subject's vault rows and a conversation's placeholders can be deleted | Erasure by subject | data a provider or tool already received is outside Taintward; with the in-memory vault, digit-only tokens can still be decrypted with the FPE key |
| Art. 25 Data protection by design and by default | supports | redaction is on by default, placeholders are the default for the LLM, and a tool nobody mapped is treated as external (masked) | Redaction before data leaves, Placeholders for the LLM, Destination and jurisdiction policy | the defaults protect what goes through Taintward; the design of the rest is yours |
| Art. 30 Records of processing activities | partly | the report lists which tools and destinations received personal data, by data class and jurisdiction | Per-call records, Sensitive data flow report | the record itself (purposes, legal basis, retention, controller details) is yours |
| Art. 32(1)(a) Pseudonymisation and encryption | supports | placeholders and FF1 tokens pseudonymise values; the vault encrypts originals with keys that can be KMS-wrapped and rotated | Placeholders for the LLM, Reversible tokens for internal sinks, Originals encrypted at rest, Key management | pseudonymised data is still personal data; FF1 here is not a validated product |
| Art. 33 and 34 Personal data breach notification | partly | shows which runs, tools and destinations got sensitive data in a window, to scope a breach | Per-call records, Tamper-evident evidence log, Sensitive data flow report | detecting the breach and notifying are yours |
| Art. 44 Transfers to third countries | partly | calls to a jurisdiction the policy marks as not adequate are flagged as transfers and counted per jurisdiction | Destination and jurisdiction policy, Sensitive data flow report | a flag from your configuration, not a legal assessment; adequacy decisions and safeguards (Art. 45 and 46) are yours |

## EU AI Act (Regulation (EU) 2024/1689)

| requirement | level | how Taintward helps | controls | limits |
|---|---|---|---|---|
| Art. 10 Data and data governance (training data) | not covered | - | - | about training, validation and testing data of high-risk systems; Taintward works at run time |
| Art. 12 Record-keeping (automatic logs) | partly | every tool and model call through Taintward is logged with its decision; violations go into a tamper-evident log | Per-call records, Tamper-evident evidence log | logs only the calls that go through Taintward; what the system's logs must hold for its purpose is the provider's to decide |
| Art. 15 Accuracy, robustness and cybersecurity | partly | limits what a prompt injection can leak: tools and the model get placeholders or masks, links in answers keep their placeholders, the gateway can block calls | Redaction before data leaves, Placeholders for the LLM, MCP gateway | does not detect or remove injected instructions, and does nothing for model accuracy |
| Art. 26(6) Deployers keep logs for at least six months | partly | the spans and the evidence log are the logs to keep | Per-call records, Tamper-evident evidence log | retention is set by your trace store and where you keep the evidence log |

## HIPAA (45 CFR Parts 160 and 164)

| requirement | level | how Taintward helps | controls | limits |
|---|---|---|---|---|
| §164.502(b) Minimum necessary | supports | the LLM and outside tools get placeholders or masks for the PHI Taintward finds | Sensitive data detection, Redaction before data leaves, Placeholders for the LLM | only the identifiers the detector finds |
| §164.514(b) De-identification (Safe Harbor) | not covered | - | Sensitive data detection | Taintward finds some of the 18 Safe Harbor identifiers (names partly, addresses, phone, email, SSN, account numbers) but not dates, ages, record or device numbers, so redacted text is not de-identified |
| §164.312(a)(2)(iv) Encryption and decryption | supports | originals in the vault are encrypted with AES-GCM under managed keys | Originals encrypted at rest, Key management | PHI stored elsewhere in your system is outside Taintward |
| §164.312(b) Audit controls | supports | calls, policy decisions and every reversal of a token are recorded | Per-call records, Tamper-evident evidence log, Audit of every reversal | only activity that goes through Taintward |
| §164.312(c)(1) Integrity | partly | changes to recorded violations are detected by the Merkle log and checkpoints | Tamper-evident evidence log | protects the evidence, not the PHI in your stores |
| §164.312(e)(1) Transmission security | partly | detected PHI is not in what is sent to the LLM or outside tools | Redaction before data leaves, Placeholders for the LLM | encryption in transit (TLS) is the connection's job |
| §164.308(a)(1)(ii)(D) Information system activity review | supports | the report is a periodic review of sensitive data flows and violations | Sensitive data flow report | reviewing it and acting on it are yours |
| §164.308(b) Business associate contracts | not covered | - | - | an LLM provider that receives PHI needs a business associate agreement; Taintward reduces what it receives but does not replace the agreement |

## SOC 2 (AICPA Trust Services Criteria)

| requirement | level | how Taintward helps | controls | limits |
|---|---|---|---|---|
| CC6.1 Logical access security and encryption keys | supports | originals are encrypted, keys can be KMS-wrapped only, rotated on a schedule | Originals encrypted at rest, Key management | user access to your systems is outside Taintward |
| CC6.7 Restricting and protecting transmission of information | supports | what each destination gets is set by policy; external and LLM calls get masks or placeholders; the gateway can block | Redaction before data leaves, Destination and jurisdiction policy, MCP gateway | only transmissions through Taintward |
| CC7.2 Monitoring for anomalies and security events | partly | egress violations and transfers are flagged on every span by the collector policy | Per-call records, Destination and jurisdiction policy | alerting on them is set up in your observability tool |
| CC7.3 Evaluating security events | partly | the report lists each violation with its trace, rule and outcome | Sensitive data flow report, Tamper-evident evidence log | the incident process is yours |
| C1.1 Identifying and protecting confidential information | partly | secrets and PII are found and redacted on the way out | Sensitive data detection, Redaction before data leaves | detection coverage has limits (docs/benchmark.md) |
| C1.2 Disposing of confidential information | partly | vault rows and placeholders can be erased by subject or conversation | Erasure by subject | copies outside the vault are yours |
| P6.1 Disclosure of personal information to third parties | partly | the report shows which third parties received personal data | Per-call records, Sensitive data flow report | consent and the disclosure policy are yours |
