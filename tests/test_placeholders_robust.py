"""Tolerant restore, the placeholder instruction and the check after restore.

Every rule here was added because a real model wrote that form in the
placeholder evaluation (bench/placeholders, docs/placeholders-eval.md).
Offline: fake data, fake models.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import re
import sys
from pathlib import Path

import pytest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.sdk import placeholders as ph
from taintward.sdk.integrations import Ward
from taintward.sdk.placeholders import PlaceholderMap, PlaceholderRestoreError

NAME, NAME2 = "Maria Garcia", "Wei Chen"
EMAIL = "maria.garcia@example.com"
SSN = "536-22-8491"
AWS = "AKIAEXAMPLEEXAMPLEE5"


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


@pytest.fixture
def m() -> PlaceholderMap:
    pm = PlaceholderMap()
    pm.placeholder_for(NAME, "PERSON")          # <PERSON_1>
    pm.placeholder_for(NAME2, "PERSON")         # <PERSON_2>
    pm.placeholder_for(EMAIL, "EMAIL_ADDRESS")  # <EMAIL_1>
    pm.placeholder_for(SSN, "US_SSN")           # <SSN_1>
    pm.placeholder_for(AWS, "AWS_ACCESS_KEY")   # <AWS_KEY_1>
    return pm


# ---------------------------------------------------------------------------
# Restore rules
# ---------------------------------------------------------------------------


class TestExactFormsStillWork:
    def test_exact_and_old_variants(self, m):
        assert m.restore_text("<PERSON_1> < SSN_1 > <person_1> &lt;SSN_1&gt;") == \
            f"{NAME} {SSN} {NAME} {SSN}"

    def test_label_with_digits(self):
        pm = PlaceholderMap()
        p = pm.placeholder_for("cert-body", "X509_CERT")
        assert p == "<X509_CERT_1>" and pm.restore_text(f"see {p}") == "see cert-body"

    def test_inner_placeholder_in_double_angle(self, m):
        # The input "Name <email>" becomes "<PERSON_1> <<EMAIL_1>>": keep the outer brackets.
        assert m.restore_text("<<EMAIL_1>>") == f"<{EMAIL}>"

    @pytest.mark.parametrize("tolerant", [True, False])
    def test_json_args_with_escaped_brackets(self, m, tolerant):
        # Ollama's OpenAI API writes tool arguments with "<" as <.
        m.tolerant = tolerant
        raw = '{"to":"\\u003cEMAIL_1\\u003e","n":"\\u003cPERSON_9\\u003e"}'
        assert json.loads(m.restore_text(raw)) == {"to": EMAIL, "n": "<PERSON_9>"}
        assert ph.check_output(m, {"arguments": raw})["unknown"] == ["<PERSON_9>"]

    def test_json_without_placeholders_is_kept_as_is(self, m):
        raw = '{"a":  "\\u003cb\\u003e"}'
        assert m.restore_text(raw) == raw

    def test_json_tool_args(self, m):
        out = json.loads(m.restore_text('{"to": "[EMAIL_1]", "body": "Hi Person_1"}'))
        assert out == {"to": EMAIL, "body": f"Hi {NAME}"}


class TestBrackets:
    @pytest.mark.parametrize("form", [
        "[PERSON_1]", "{PERSON_1}", "{{PERSON_1}}", "[[PERSON_1]]", "(PERSON_1)",
        "«PERSON_1»", "‹PERSON_1›", "〈PERSON_1〉", "《PERSON_1》", "【PERSON_1】",
        "「PERSON_1」", "＜PERSON_1＞", "[ PERSON_1 ]",
    ])
    def test_other_brackets(self, m, form):
        assert m.restore_text(f"Dear {form},") == f"Dear {NAME},"

    @pytest.mark.parametrize("form", [
        "<Person 1>", "<PERSON-1>", "<Person1>", "[Person 1]", "[Email 1]", "<aws key_1>",
        "[AWS KEY 1]",
    ])
    def test_separators_and_case_inside_brackets(self, m, form):
        out = m.restore_text(form)
        assert out in (NAME, EMAIL, AWS)

    def test_markdown_escapes(self, m):
        assert m.restore_text(r"\<PERSON\_1\> and PERSON\_2") == f"{NAME} and {NAME2}"

    def test_full_width_letters(self, m):
        assert m.restore_text("＜ＰＥＲＳＯＮ＿１＞さん") == f"{NAME}さん"

    def test_template_slots_are_left_alone(self, m):
        text = "[Your Name] [Recipient's Full Name] [Step 3] (2) [Date]"
        assert m.restore_text(text) == text
        assert m.diagnose(text) == {"repaired": [], "lost": [], "unknown": [], "blocked": []}


class TestBare:
    def test_upper_and_title_case(self, m):
        assert m.restore_text("Caller: PERSON_1, key AWS_KEY_1, Person_2") == \
            f"Caller: {NAME}, key {AWS}, {NAME2}"

    def test_lower_case_is_never_restored(self, m):
        # could be a variable name in code
        assert m.restore_text("aws_key_1 = load()") == "aws_key_1 = load()"
        assert m.diagnose("aws_key_1 = load()")["lost"] == ["aws_key_1"]

    def test_unknown_labels_and_numbers(self, m):
        text = "MY_VAR_1 user_1@example.com maria_garcia_2@example.org"
        assert m.restore_text(text) == text

    def test_table_cell(self, m):
        assert m.restore_text("| Lukas | SSN_1 |") == f"| Lukas | {SSN} |"


class TestSpaced:
    def test_restored_when_unambiguous(self, m):
        assert m.restore_text("Please call Person 1 today.") == f"Please call {NAME} today."
        assert m.restore_text("PERSON 2 and Person-1") == f"{NAME2} and {NAME}"

    def test_not_restored_next_to_a_real_placeholder(self, m):
        # "Person 1" next to <PERSON_2> is more likely a list number.
        text = "Person 1 and <PERSON_2>"
        assert m.restore_text(text) == f"Person 1 and {NAME2}"
        assert m.diagnose(text)["lost"] == ["Person 1"]

    def test_not_restored_when_numbers_go_past_the_map(self, m):
        # Person 3 does not exist: this is an enumeration, touch none of it.
        text = "Person 1, Person 2, Person 3"
        assert m.restore_text(text) == text

    def test_lower_case_and_other_words(self, m):
        text = "person 1, Step 1, Table 2, SSN 536-22"
        assert m.restore_text(text) == text

    def test_values_that_follow_a_label_are_not_numbers(self, m):
        assert m.restore_text("SSN 701-18-4420") == "SSN 701-18-4420"
        assert m.restore_text("Card 4111 1111") == "Card 4111 1111"


class TestAliases:
    @pytest.mark.parametrize("form", ["<PERSONA_1>", "<PERSONNE_1>", "[NAME_1]", "<NOMBRE_1>"])
    def test_translated_label(self, m, form):
        assert m.restore_text(form) == NAME

    def test_translated_label_in_japanese(self, m):
        assert m.restore_text("契約を＜名前_1＞（＜メールアドレス_1＞）に") == f"契約を{NAME}（{EMAIL}）に"

    def test_markdown_escaped_open_bracket(self, m):
        assert m.restore_text(r"Dear \[PERSON_1],") == f"Dear {NAME},"

    def test_alias_not_used_when_it_is_a_real_label(self):
        pm = PlaceholderMap()
        pm.placeholder_for("Maria Garcia", "PERSON")
        pm.placeholder_for("db-prod", "NAME")  # a custom entity type called NAME
        assert pm.restore_text("<NAME_1>") == "db-prod"
        assert pm.restore_text("<NAME_2>") == "<NAME_2>"

    def test_spaced_form_has_no_aliases(self, m):
        assert m.restore_text("Name 1") == "Name 1"


class TestNeverInvent:
    def test_unknown_number_left_and_reported(self, m):
        text = "<PERSON_3> [PERSON_9] PHONE_1"
        assert m.restore_text(text) == text
        assert m.diagnose(text)["unknown"] == ["<PERSON_3>", "[PERSON_9]", "PHONE_1"]

    def test_numberless_is_lost(self, m):
        assert m.restore_text("Dear <PERSON>,") == "Dear <PERSON>,"
        assert m.diagnose("Dear <PERSON>,")["lost"] == ["<PERSON>"]

    def test_restored_value_is_not_scanned_again(self):
        pm = PlaceholderMap()
        pm.placeholder_for("value PERSON_2", "PERSON")
        pm.placeholder_for("Bob Stone", "PERSON")
        assert pm.restore_text("[PERSON_1]") == "value PERSON_2"

    def test_empty_map_changes_nothing(self):
        assert PlaceholderMap().restore_text("[PERSON_1] Person 1") == "[PERSON_1] Person 1"


class TestStrictOff:
    def test_tolerant_false_is_the_old_behaviour(self, m):
        m.tolerant = False
        text = "[PERSON_1] PERSON_1 Person 1 <PERSONA_1>"
        assert m.restore_text(text) == text
        assert m.restore_text("<person_1>") == NAME


class TestDiagnose:
    def test_kinds(self, m):
        d = m.diagnose("<PERSON_1> [EMAIL_1] <PERSON_7> <SSN>")
        assert d == {"repaired": ["[EMAIL_1]"], "lost": ["<SSN>"], "unknown": ["<PERSON_7>"],
                     "blocked": []}

    def test_never_returns_values(self, m):
        d = m.diagnose(f"[PERSON_1] <PERSON_5> {NAME}")
        assert NAME not in json.dumps(d)


# ---------------------------------------------------------------------------
# check_output, the instruction, strict mode (through the real adapters)
# ---------------------------------------------------------------------------


@pytest.fixture
def otel():
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider.get_tracer("taintward"), exporter
    provider.shutdown()


class _Span:
    def __init__(self):
        self.attrs = {}

    def set_attribute(self, k, v):
        self.attrs[k] = v


class TestCheckOutput:
    def test_records_and_warns(self, m, caplog):
        span = _Span()
        with caplog.at_level(logging.WARNING, logger="taintward.sdk"):
            found = ph.check_output(m, {"content": "Hi [PERSON_1] and <PERSON_4>"}, span=span)
        assert found["unknown"] == ["<PERSON_4>"]
        assert span.attrs["taintward.placeholders.unknown"] == ["<PERSON_4>"]
        assert span.attrs["taintward.placeholders.repaired"] == ["[PERSON_1]"]
        assert "could not be restored" in caplog.text and NAME not in caplog.text

    def test_clean_answer_no_warning(self, m, caplog):
        with caplog.at_level(logging.WARNING, logger="taintward.sdk"):
            ph.check_output(m, ["<PERSON_1>", {"a": "<SSN_1>"}])
        assert not caplog.records

    def test_strict_raises(self, m):
        with pytest.raises(PlaceholderRestoreError) as e:
            ph.check_output(m, "Dear <PERSON>", strict=True)
        assert e.value.lost == ["<PERSON>"]


def test_placeholders_in_and_instruction():
    names = ph.placeholders_in({"messages": [{"content": "a <PERSON_1> b <ssn_1> <PERSON_1>"}]})
    assert names == ["<PERSON_1>", "<SSN_1>"]
    line = ph.instruction_for(names)
    assert "<PERSON_1>, <SSN_1>" in line and "Copy each placeholder exactly" in line
    many = ph.instruction_for([f"<PERSON_{i}>" for i in range(1, 40)])
    assert "<PERSON_20>, ..." in many and "<PERSON_21>" not in many


needs_openai = pytest.mark.skipif(not (_has("openai") and _has("httpx")),
                                  reason="openai not installed")


def _openai(bodies, content):
    import httpx
    import openai

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "c1", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    return openai.OpenAI(api_key="t", base_url="http://fake.local/v1",
                         http_client=httpx.Client(transport=httpx.MockTransport(handler)))


@needs_openai
class TestOpenAIAdapter:
    def test_instruction_added_and_rewrite_restored(self, otel):
        tracer, exporter = otel
        ward = Ward(tracer=tracer)
        bodies = []
        client = ward.protect_openai(_openai(bodies, "Dear [PERSON_1], see <PERSON_5>."))
        with ward.run("r"):
            resp = client.chat.completions.create(model="m", messages=[
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": f"Write to {NAME} ({EMAIL})."}])
        msgs = bodies[0]["messages"]
        assert len(msgs) == 2 and msgs[0]["content"].startswith("Be brief.\n\nSome values")
        assert "<PERSON_1>, <EMAIL_1>" in msgs[0]["content"]
        assert NAME not in json.dumps(bodies[0])
        assert resp.choices[0].message.content == f"Dear {NAME}, see <PERSON_5>."
        span = [s for s in exporter.get_finished_spans() if s.name == "chat m"][0]
        assert span.attributes["taintward.placeholders.instruction"] is True
        assert list(span.attributes["taintward.placeholders.unknown"]) == ["<PERSON_5>"]

    def test_instruction_new_system_message(self, otel):
        ward = Ward(tracer=otel[0])
        bodies = []
        client = ward.protect_openai(_openai(bodies, "ok"))
        with ward.run("r"):
            client.chat.completions.create(model="m", messages=[
                {"role": "user", "content": f"Hi, I am {NAME}."}])
        assert bodies[0]["messages"][0]["role"] == "system"
        assert bodies[0]["messages"][1]["content"] == "Hi, I am <PERSON_1>."

    def test_no_instruction_without_placeholders(self, otel):
        ward = Ward(tracer=otel[0])
        bodies = []
        client = ward.protect_openai(_openai(bodies, "ok"))
        with ward.run("r"):
            client.chat.completions.create(model="m", messages=[
                {"role": "user", "content": "What is 2 + 2?"}])
        assert len(bodies[0]["messages"]) == 1

    def test_opt_out(self, otel):
        ward = Ward(tracer=otel[0], placeholder_instruction=False)
        bodies = []
        client = ward.protect_openai(_openai(bodies, "ok"))
        with ward.run("r"):
            client.chat.completions.create(model="m", messages=[
                {"role": "user", "content": f"Hi, I am {NAME}."}])
        assert len(bodies[0]["messages"]) == 1

    def test_strict_mode_raises(self, otel):
        ward = Ward(tracer=otel[0], placeholder_strict=True)
        client = ward.protect_openai(_openai([], "Dear <PERSON_3>"))
        with ward.run("r"), pytest.raises(PlaceholderRestoreError):
            client.chat.completions.create(model="m", messages=[
                {"role": "user", "content": f"Hi, I am {NAME}."}])


@pytest.mark.skipif(not (_has("anthropic") and _has("httpx")), reason="anthropic not installed")
def test_anthropic_instruction_goes_to_system(otel):
    import anthropic
    try:
        import httpx2 as httpx
    except ImportError:
        import httpx
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "m1", "type": "message", "role": "assistant", "model": "c",
            "content": [{"type": "text", "text": "Hello Person 1."}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}})

    ward = Ward(tracer=otel[0])
    client = ward.protect_anthropic(anthropic.Anthropic(
        api_key="t", base_url="http://fake.local",
        http_client=httpx.Client(transport=httpx.MockTransport(handler))))
    with ward.run("r"):
        resp = client.messages.create(model="c", max_tokens=10, system="Be brief.",
                                      messages=[{"role": "user", "content": f"I am {NAME}."}])
    assert bodies[0]["system"].startswith("Be brief.\n\nSome values")
    assert resp.content[0].text == f"Hello {NAME}."


@pytest.mark.skipif(not _has("langchain_core"), reason="langchain not installed")
def test_langchain_instruction_and_tolerant_restore(otel):
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    seen = []

    class Fake(GenericFakeChatModel):
        def _generate(self, messages, *a, **kw):
            seen.append(messages)
            return super()._generate(messages, *a, **kw)

    ward = Ward(tracer=otel[0])
    model = ward.protect_langchain_model(Fake(messages=iter([AIMessage("Dear PERSON_1,")])))
    with ward.run("r"):
        out = model.invoke(f"Write to {NAME}.")
    assert seen[0][0].type == "system" and "<PERSON_1>" in seen[0][0].content
    assert out.content == f"Dear {NAME},"


# ---------------------------------------------------------------------------
# Harness smoke test (bench/placeholders) with a fake model
# ---------------------------------------------------------------------------

BENCH = Path(__file__).resolve().parent.parent / "bench" / "placeholders"


@needs_openai
def test_harness_smoke_with_fake_model():
    import httpx
    sys.path.insert(0, str(BENCH))
    try:
        import harness
    finally:
        sys.path.remove(str(BENCH))

    def handler(request):
        # A model that copies every placeholder of the last user message,
        # but in square brackets (a rewrite real models do).
        body = json.loads(request.content)
        user = [x for x in body["messages"] if x["role"] == "user"][-1]["content"]
        names = re.findall(r"<([A-Z_]+_\d+)>", user)
        text = "To: " + " ".join(f"[{n}]" for n in names) + "\nDear " + \
            " ".join(f"[{n}]" for n in names)
        return httpx.Response(200, json={
            "id": "c1", "object": "chat.completion", "created": 1, "model": "fake",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def backend(ward):
        return harness.OpenAIBackend(ward, "fake", "http://fake.local/v1", "t",
                                     transport=httpx.MockTransport(handler))

    ids = ["email-refund", "translate-es", "summary-incident"]
    base = harness.run_model("fake", "fake", "baseline", ids, backend=backend)
    hard = harness.run_model("fake", "fake", "hardened", ids, backend=backend)
    assert base["summary"]["restore_ok"] == 0 and base["summary"]["leftover_tasks"] == 3
    assert hard["summary"]["restore_ok"] == 3, [r["problems"] for r in hard["results"]]
    for run in (base, hard):
        assert run["summary"]["leak_known"] == 0
    assert all(r["instruction_sent"] for r in hard["results"])
    assert not any(r["instruction_sent"] for r in base["results"])
    assert harness.rescore(hard)["summary"]["restore_ok"] == 3
    assert harness.leftovers("SSN 701-18-4420, [Your Name]") == []
    assert harness.leftovers("Dear [PERSON_1] and Person 2") == ["[PERSON_1]", "Person 2"]
