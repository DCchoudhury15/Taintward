package taintpolicy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const rawSSN = "234-12-1234"

// run sends one prepared trace through a default processor and returns the
// forwarded copy.
func run(t *testing.T, cfg *Config, td ptrace.Traces) ptrace.Traces {
	t.Helper()
	s := &sink{}
	p, err := newProcessor(cfg, s)
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	if err := p.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	return s.got
}

func defaultCfg() *Config { return createDefaultConfig().(*Config) }

func firstSpan(td ptrace.Traces) ptrace.Span {
	return td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
}

// dump renders every string on the forwarded traces, so a test can assert
// that a raw value appears nowhere.
func dump(td ptrace.Traces) string {
	var b strings.Builder
	var val func(v pcommon.Value)
	val = func(v pcommon.Value) {
		switch v.Type() {
		case pcommon.ValueTypeMap:
			v.Map().Range(func(k string, x pcommon.Value) bool { b.WriteString(k + "="); val(x); return true })
		case pcommon.ValueTypeSlice:
			for i := 0; i < v.Slice().Len(); i++ {
				val(v.Slice().At(i))
			}
		case pcommon.ValueTypeBytes:
			b.Write(v.Bytes().AsRaw())
		default:
			b.WriteString(v.AsString())
		}
		b.WriteString(";")
	}
	m := func(m pcommon.Map) {
		m.Range(func(k string, v pcommon.Value) bool { b.WriteString(k + "="); val(v); return true })
	}
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)
		m(rs.Resource().Attributes())
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			m(ss.Scope().Attributes())
			for k := 0; k < ss.Spans().Len(); k++ {
				sp := ss.Spans().At(k)
				b.WriteString(sp.Name() + ";" + sp.Status().Message() + ";")
				m(sp.Attributes())
				for e := 0; e < sp.Events().Len(); e++ {
					b.WriteString(sp.Events().At(e).Name() + ";")
					m(sp.Events().At(e).Attributes())
				}
				for l := 0; l < sp.Links().Len(); l++ {
					m(sp.Links().At(l).Attributes())
				}
			}
		}
	}
	return b.String()
}

func assertNoRaw(t *testing.T, td ptrace.Traces, raws ...string) {
	t.Helper()
	d := dump(td)
	for _, r := range raws {
		if strings.Contains(d, r) {
			t.Errorf("raw value %q reached the backend:\n%s", r, d)
		}
	}
}

// --- item 1: gen_ai.tool.call.arguments ---

func TestArgs_RedactedWithoutMarker(t *testing.T) {
	td := ptrace.NewTraces()
	sp := newSpan(td, "send_email")
	sp.Attributes().PutBool("taintward.sensitive", true)
	sp.Attributes().PutStr("gen_ai.tool.call.arguments", `{"kwargs":{"ssn":"`+rawSSN+`"}}`)
	got := run(t, defaultCfg(), td)
	assertNoRaw(t, got, rawSSN)
}

func TestArgs_RedactedWhenDryRun(t *testing.T) {
	// SDK dry-run sends raw args and sets taintward.dry_run, not the marker.
	td := ptrace.NewTraces()
	sp := newSpan(td, "send_email")
	sp.Attributes().PutBool("taintward.dry_run", true)
	sp.Attributes().PutBool("taintward.redacted", false)
	sp.Attributes().PutStr("gen_ai.tool.call.arguments", `{"kwargs":{"ssn":"`+rawSSN+`"}}`)
	got := run(t, defaultCfg(), td)
	assertNoRaw(t, got, rawSSN)
}

func TestArgs_LegacyRedactedFlagIsNotTheMarker(t *testing.T) {
	// taintward.redacted=true only means "the gate changed the input"; a
	// passthrough kwarg can still be raw. It must not disable redaction.
	td := ptrace.NewTraces()
	sp := newSpan(td, "send_email")
	sp.Attributes().PutBool("taintward.redacted", true)
	sp.Attributes().PutStr("gen_ai.tool.call.arguments", `{"kwargs":{"to":"jane@example.com"}}`)
	got := run(t, defaultCfg(), td)
	assertNoRaw(t, got, "jane@example.com")
}

func TestArgs_NonStringArgsRedacted(t *testing.T) {
	td := ptrace.NewTraces()
	sp := newSpan(td, "send_email")
	m := sp.Attributes().PutEmptyMap("gen_ai.tool.call.arguments")
	m.PutStr("ssn", rawSSN)
	got := run(t, defaultCfg(), td)
	assertNoRaw(t, got, rawSSN)
}

func TestArgs_SkippedWhenMarkerSet(t *testing.T) {
	// FPE token that looks like an SSN must survive when the SDK says it
	// already redacted the args.
	const fpe = `{"kwargs":{"ssn":"871-55-0392"}}`
	td := ptrace.NewTraces()
	sp := newSpan(td, "query_db")
	sp.Attributes().PutBool("taintward.sensitive", true)
	sp.Attributes().PutBool("taintward.args_redacted", true)
	sp.Attributes().PutStr("gen_ai.tool.call.arguments", fpe)
	sp.Attributes().PutStr("gen_ai.tool.call.result", `{"ssn":"`+rawSSN+`"}`)
	got := firstSpan(run(t, defaultCfg(), td)).Attributes()
	if s := strAttr(got, "gen_ai.tool.call.arguments"); s != fpe {
		t.Errorf("args changed despite marker: %q", s)
	}
	if strings.Contains(strAttr(got, "gen_ai.tool.call.result"), rawSSN) {
		t.Error("marker must only skip the args attribute, result was not redacted")
	}
}

func TestArgs_StringMarkerNotAccepted(t *testing.T) {
	td := ptrace.NewTraces()
	sp := newSpan(td, "query_db")
	sp.Attributes().PutStr("taintward.args_redacted", "true")
	sp.Attributes().PutStr("gen_ai.tool.call.arguments", rawSSN)
	assertNoRaw(t, run(t, defaultCfg(), td), rawSSN)
}

// --- item 2: everywhere on the span, nested, normalized, new patterns ---

func TestRedact_NestedMapAndSlice(t *testing.T) {
	td := ptrace.NewTraces()
	sp := newSpan(td, "x")
	m := sp.Attributes().PutEmptyMap("payload")
	inner := m.PutEmptyMap("user")
	inner.PutStr("ssn", rawSSN)
	sl := inner.PutEmptySlice("emails")
	sl.AppendEmpty().SetStr("jane@example.com")
	deep := sl.AppendEmpty().SetEmptySlice()
	deep.AppendEmpty().SetEmptyMap().PutStr("k", "AKIAIOSFODNN7EXAMPLE")
	sp.Attributes().PutEmptyBytes("blob").FromRaw([]byte("ssn " + rawSSN))
	got := run(t, defaultCfg(), td)
	assertNoRaw(t, got, rawSSN, "jane@example.com", "AKIAIOSFODNN7EXAMPLE")
	if n, _ := firstSpan(got).Attributes().Get("taintward.policy.masked_values"); n.Int() != 4 {
		t.Errorf("masked_values = %d, want 4", n.Int())
	}
}

func TestRedact_TooDeepIsReplaced(t *testing.T) {
	td := ptrace.NewTraces()
	sp := newSpan(td, "x")
	m := sp.Attributes().PutEmptyMap("d")
	for i := 0; i < maxDepth+5; i++ {
		m = m.PutEmptyMap("n")
	}
	m.PutStr("hidden", "nothing matches this")
	got := run(t, defaultCfg(), td)
	if strings.Contains(dump(got), "nothing matches this") {
		t.Error("value below maxDepth was stored unscanned")
	}
}

func TestRedact_EventsNameStatusLinksResource(t *testing.T) {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("user.email", "ops@example.com")
	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().Attributes().PutStr("owner", "lead@example.com")
	sp := ss.Spans().AppendEmpty()
	sp.SetName("lookup " + rawSSN)
	sp.Status().SetCode(ptrace.StatusCodeError)
	sp.Status().SetMessage("bad card 4111 1111 1111 1111")
	ev := sp.Events().AppendEmpty()
	ev.SetName("exception")
	ev.Attributes().PutStr("exception.message", "ValueError: invalid ssn "+rawSSN)
	ev.Attributes().PutStr("exception.stacktrace", "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ln := sp.Links().AppendEmpty()
	ln.Attributes().PutStr("note", "from jane@example.com")

	got := run(t, defaultCfg(), td)
	assertNoRaw(t, got, rawSSN, "ops@example.com", "lead@example.com",
		"4111 1111 1111 1111", "ghp_aaaa", "jane@example.com")
	gs := firstSpan(got)
	if gs.Name() != "lookup [PII]" {
		t.Errorf("span name = %q", gs.Name())
	}
	if gs.Status().Code() != ptrace.StatusCodeError {
		t.Error("status code changed")
	}
}

func TestMask_Table(t *testing.T) {
	cases := []struct {
		name, in string
		masked   bool
		raw      string // must not survive when masked
	}{
		{"ssn dashes", "ssn 234-12-1234", true, "234-12-1234"},
		{"ssn spaces", "id 234 12 1234 x", true, "234 12 1234"},
		{"ssn fullwidth", "\uff33\uff33\uff2e \uff12\uff13\uff14\uff0d\uff11\uff12\uff0d\uff11\uff12\uff13\uff14", true, "234"},
		{"ssn fullwidth digits ascii dash", "\uff12\uff13\uff14-\uff11\uff12-\uff11\uff12\uff13\uff14", true, "\uff11\uff12\uff13\uff14"},
		{"ssn zero width", "234\u200b-12\u200c-12\u200d34", true, "12\u200d34"},
		{"ssn arabic-indic digits", "\u0662\u0663\u0664-\u0661\u0662-\u0661\u0662\u0663\u0664", true, "\u0661\u0662\u0663\u0664"},
		{"ssn bare with keyword", `{"ssn": "234121234"}`, true, "234121234"},
		{"ssn bare with keyword number", `{"SSN":234121234}`, true, "234121234"},
		{"ssn social security number", "Social Security Number: 234121234", true, "234121234"},
		{"bare 9 digits no keyword", `{"order_id": 234121234}`, false, ""},
		{"zip+4 no keyword", "zip 941071234", false, ""},
		{"visa spaced", "card 4111 1111 1111 1111 ok", true, "4111 1111 1111 1111"},
		{"visa plain", "4111111111111111", true, "4111111111111111"},
		{"mastercard dashes", "5555-5555-5555-4444", true, "5555-5555-5555-4444"},
		{"amex", "378282246310005", true, "378282246310005"},
		{"card bad luhn", "4111111111111112", false, ""},
		{"unix ms timestamp", `{"ts":1729876543210}`, false, ""},
		{"unix ns timestamp", `{"ts":1729876543210123456}`, false, ""},
		// Token fixtures are split so secret scanners do not flag them.
		{"openai key", "key sk-" + "proj-abcdefghijklmnopqrstuvwx", true, "abcdefghijklmnop"},
		{"slack token", "xoxb-" + "1234567890-abcdefghij", true, "xoxb-1234567890"},
		{"google key", "AIza" + "SyA1234567890abcdefghijklmnopqrstuv", true, "AIzaSyA12345"},
		{"github fine grained", "github_pat_" + "11ABCDEFG0123456789_abcdefghij", true, "github_pat_11"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", true, "eyJhbGci"},
		{"password assign", `{"password": "hunter2hunter2"}`, true, "hunter2hunter2"},
		{"api_key assign", "api_key=Zx81hjq0Lmn42Pqr", true, "Zx81hjq0Lmn42Pqr"},
		{"bearer", "Authorization: Bearer abcdefghijklmnop1234", true, "abcdefghijklmnop1234"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", true, "MIIEow"},
		{"token count not a secret", `{"token_count": 12345678, "max_tokens": 4096}`, false, ""},
		{"plain text", "weekly report for team alpha", false, ""},
		{"non-ascii clean", "café über naïve 東京", false, ""},
		{"phone", "call 415-555-0123", true, "415-555-0123"},
		{"email", "mail jane.doe@example.co.uk", true, "jane.doe@example.co.uk"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, hit := maskString(c.in)
			if hit != c.masked {
				t.Fatalf("maskString(%q) hit=%v out=%q, want hit=%v", c.in, hit, out, c.masked)
			}
			if !hit && out != c.in {
				t.Fatalf("unmasked input changed: %q -> %q", c.in, out)
			}
			if hit && c.raw != "" && strings.Contains(out, c.raw) {
				t.Fatalf("raw %q survived: %q", c.raw, out)
			}
		})
	}
}

func TestMask_NoAllocOnCleanASCII(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under -race")
	}
	s := `{"status":"ok","rows":42,"note":"nothing sensitive: here = fine"}`
	if n := testing.AllocsPerRun(100, func() { maskString(s) }); n != 0 {
		t.Errorf("maskString on clean ASCII allocates %.0f times, want 0", n)
	}
}

// --- item 3: fail closed ---

func TestFailClosed_RegoErrorStillRedacts(t *testing.T) {
	// Valid at startup (probes do not trigger it), errors at runtime for a
	// specific tool: a builtin error with strict-builtin semantics comes from
	// a conflict in a complete rule.
	pol := `package taintward

import rego.v1

default redact := false

redact if input.sensitive == true

decision := {"redact": redact, "violations": set()} if input.tool != "boom"

decision := {"redact": true, "violations": set()} if input.tool == "boom"

decision := {"redact": false, "violations": set()} if input.tool == "boom"
`
	path := filepath.Join(t.TempDir(), "p.rego")
	if err := os.WriteFile(path, []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	td := ptrace.NewTraces()
	sp := newSpan(td, "x")
	sp.Attributes().PutStr("gen_ai.tool.name", "boom")
	sp.Attributes().PutBool("taintward.policy.violation", false)     // spoofed by producer
	sp.Attributes().PutStr("taintward.policy.rules", "gateway_rule") // gateway-owned, kept
	sp.Attributes().PutStr("gen_ai.tool.call.result", rawSSN)
	got := run(t, &Config{PolicyPath: path, DecisionCacheSize: 16}, td)
	assertNoRaw(t, got, rawSSN)
	a := firstSpan(got).Attributes()
	if strAttr(a, "taintward.policy.error") == "" {
		t.Error("taintward.policy.error not recorded on eval error")
	}
	if !boolAttr(a, "taintward.policy.redacted") {
		t.Error("policy.redacted should be true on fail closed")
	}
	if _, ok := a.Get("taintward.policy.violation"); ok {
		t.Error("spoofed taintward.policy.violation survived a policy error")
	}
	if strAttr(a, "taintward.policy.rules") != "gateway_rule" {
		t.Error("gateway-owned taintward.policy.rules was removed")
	}
}

func TestFailClosed_UndefinedDecisionStillRedacts(t *testing.T) {
	// decision defined for the probe inputs only.
	pol := `package taintward

import rego.v1

default redact := false

redact if input.sensitive == true

decision := {"redact": redact, "violations": set()} if input.tool == ""
`
	path := filepath.Join(t.TempDir(), "p.rego")
	if err := os.WriteFile(path, []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	td := ptrace.NewTraces()
	sp := newSpan(td, "x")
	sp.Attributes().PutStr("gen_ai.tool.name", "other")
	sp.Attributes().PutStr("gen_ai.tool.call.result", rawSSN)
	got := run(t, &Config{PolicyPath: path}, td)
	assertNoRaw(t, got, rawSSN)
	if !strings.Contains(strAttr(firstSpan(got).Attributes(), "taintward.policy.error"), "undefined") {
		t.Error("undefined decision not recorded as policy error")
	}
}

func TestSensitive_StringTrue(t *testing.T) {
	for _, v := range []string{"true", "TRUE", " 1 "} {
		td := ptrace.NewTraces()
		sp := newSpan(td, "x")
		sp.Attributes().PutStr("taintward.sensitive", v)
		sp.Attributes().PutStr("taintward.destination", "external")
		a := firstSpan(run(t, defaultCfg(), td)).Attributes()
		if !boolAttr(a, "taintward.policy.redacted") || !boolAttr(a, "taintward.policy.violation") {
			t.Errorf("sensitive=%q not treated as true", v)
		}
	}
}

func TestSensitive_MissingStillRedactsRawSSN(t *testing.T) {
	td := ptrace.NewTraces()
	sp := newSpan(td, "plain_otel_span") // another producer, no taintward attrs
	sp.Attributes().PutStr("db.statement", "SELECT * FROM users WHERE ssn='"+rawSSN+"'")
	got := run(t, defaultCfg(), td)
	assertNoRaw(t, got, rawSSN)
	a := firstSpan(got).Attributes()
	if boolAttr(a, "taintward.policy.violation") {
		t.Error("no violation expected for a non-sensitive span")
	}
	if strAttr(a, "taintward.policy.decision_engine") != "rego" {
		t.Error("decision must be recorded for every span (default redact := false)")
	}
}

func TestStartup_RejectsWrongPackage(t *testing.T) {
	pol := strings.Replace(embeddedPolicy, "package taintward", "package acme", 1)
	path := filepath.Join(t.TempDir(), "p.rego")
	_ = os.WriteFile(path, []byte(pol), 0o644)
	_, err := newProcessor(&Config{PolicyPath: path}, &sink{})
	if err == nil || !strings.Contains(err.Error(), "package") {
		t.Fatalf("want a clear package error, got %v", err)
	}
}

func TestStartup_RejectsMissingRules(t *testing.T) {
	pol := "package taintward\n\nimport rego.v1\n\nallow := true\n"
	path := filepath.Join(t.TempDir(), "p.rego")
	_ = os.WriteFile(path, []byte(pol), 0o644)
	_, err := newProcessor(&Config{PolicyPath: path}, &sink{})
	if err == nil || !strings.Contains(err.Error(), `"decision"`) {
		t.Fatalf("want missing-rule error, got %v", err)
	}
}

func TestStartup_RejectsMissingRedactDefault(t *testing.T) {
	pol := strings.Replace(embeddedPolicy, "default redact := false\n", "", 1)
	path := filepath.Join(t.TempDir(), "p.rego")
	_ = os.WriteFile(path, []byte(pol), 0o644)
	_, err := newProcessor(&Config{PolicyPath: path}, &sink{})
	if err == nil || !strings.Contains(err.Error(), "probe") {
		t.Fatalf("want probe failure for a policy with no redact default, got %v", err)
	}
}

func TestStartup_RejectsNegativeCache(t *testing.T) {
	if _, err := newProcessor(&Config{DecisionCacheSize: -1}, &sink{}); err == nil {
		t.Fatal("negative decision_cache_size accepted")
	}
}

// --- item 4: jurisdiction case ---

func TestPolicy_UppercaseUSIsTransfer(t *testing.T) {
	td := ptrace.NewTraces()
	sp := newSpan(td, "ask_llm")
	sp.Attributes().PutBool("taintward.sensitive", true)
	sp.Attributes().PutStr("taintward.taint.classes", "PII, Secret")
	sp.Attributes().PutStr("taintward.destination", "LLM")
	sp.Attributes().PutStr("taintward.jurisdiction", "US")
	a := firstSpan(run(t, defaultCfg(), td)).Attributes()
	if !boolAttr(a, "taintward.policy.transfer_violation") {
		t.Error("jurisdiction \"US\" did not trigger the transfer rule")
	}
	if !boolAttr(a, "taintward.policy.violation") {
		t.Error("destination \"LLM\" did not trigger the egress rule")
	}
}

func TestPolicy_RegoItselfIsCaseInsensitive(t *testing.T) {
	// Evaluate the policy directly with raw upper-case input, without the
	// Go-side lower-casing, so a custom caller cannot reintroduce the bug.
	q, err := rego.New(rego.Query("data.taintward.decision"),
		rego.Module("p.rego", embeddedPolicy)).PrepareForEval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rs, err := q.Eval(context.Background(), rego.EvalInput(map[string]interface{}{
		"sensitive": true, "classes": "PII", "destination": "External", "jurisdiction": " US ", "tool": "",
	}))
	if err != nil || len(rs) == 0 {
		t.Fatalf("eval: %v", err)
	}
	vs := rs[0].Expressions[0].Value.(map[string]interface{})["violations"].([]interface{})
	rules := map[string]bool{}
	for _, v := range vs {
		rules[v.(map[string]interface{})["rule"].(string)] = true
	}
	if !rules["transfer"] || !rules["pii_egress"] {
		t.Errorf("violations = %v, want transfer + pii_egress", vs)
	}
}

func TestPolicy_EmbeddedMatchesCanonical(t *testing.T) {
	canonical, err := os.ReadFile(filepath.Join("..", "..", "policy", "pii_egress.rego"))
	if err != nil {
		t.Fatalf("read canonical policy: %v", err)
	}
	if !bytes.Equal(canonical, []byte(embeddedPolicy)) {
		t.Fatal("collector/policy/pii_egress.rego and the embedded copy differ; copy the canonical file over the embedded one")
	}
}

// --- cache ---

func TestCache_SameDecisionAsUncached(t *testing.T) {
	mk := func() ptrace.Traces {
		td := ptrace.NewTraces()
		sp := newSpan(td, "x")
		sp.Attributes().PutBool("taintward.sensitive", true)
		sp.Attributes().PutStr("taintward.taint.classes", "pii")
		sp.Attributes().PutStr("taintward.destination", "external")
		sp.Attributes().PutStr("taintward.jurisdiction", "us")
		return td
	}
	s := &sink{}
	p, err := newProcessor(&Config{DecisionCacheSize: 1}, s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ { // miss, hit, hit
		_ = p.ConsumeTraces(context.Background(), mk())
		a := firstSpan(s.got).Attributes()
		if strAttr(a, "taintward.policy.reasons") != "transfer,pii_egress" {
			t.Fatalf("run %d: reasons = %q", i, strAttr(a, "taintward.policy.reasons"))
		}
	}
	uncached := firstSpan(run(t, &Config{DecisionCacheSize: 0}, mk())).Attributes()
	if strAttr(uncached, "taintward.policy.violations") != strAttr(firstSpan(s.got).Attributes(), "taintward.policy.violations") {
		t.Error("cached and uncached decisions differ")
	}
}
