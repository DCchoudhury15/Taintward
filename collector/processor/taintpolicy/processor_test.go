package taintpolicy

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// sink is a next-consumer that captures the traces the processor forwards.
type sink struct {
	got ptrace.Traces
}

func (s *sink) Capabilities() consumer.Capabilities { return consumer.Capabilities{MutatesData: false} }
func (s *sink) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	s.got = ptrace.NewTraces()
	td.CopyTo(s.got)
	return nil
}

func newSpan(td ptrace.Traces, name string) ptrace.Span {
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName(name)
	return span
}

func strAttr(m pcommon.Map, k string) string {
	v, ok := m.Get(k)
	if !ok || v.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return v.Str()
}

func boolAttr(m pcommon.Map, k string) bool {
	v, ok := m.Get(k)
	if !ok || v.Type() != pcommon.ValueTypeBool {
		return false
	}
	return v.Bool()
}

func TestProcessor_EgressAndTransferAndRedact(t *testing.T) {
	s := &sink{}
	p, err := newProcessor(&Config{}, s)
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}

	td := ptrace.NewTraces()
	// A tainted span reaching an external US sink: should violate + transfer + redact.
	span := newSpan(td, "call_external_api")
	span.Attributes().PutBool("taintward.sensitive", true)
	span.Attributes().PutStr("taintward.taint.classes", "pii,secret")
	span.Attributes().PutStr("taintward.destination", "external")
	span.Attributes().PutStr("taintward.jurisdiction", "us")
	// Raw PII the SDK left in a string attr (mask-in-SDK off): collector must redact.
	span.Attributes().PutStr("gen_ai.tool.call.result", `{"ssn":"234-12-1234","key":"AKIAIOSFODNN7EXAMPLE"}`)

	if err := p.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if s.got.ResourceSpans().Len() == 0 {
		t.Fatal("processor did not forward traces to next consumer")
	}
	attrs := s.got.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()

	if got := strAttr(attrs, "taintward.policy.decision_engine"); got != "rego" {
		t.Errorf("decision_engine = %q, want rego", got)
	}
	if !boolAttr(attrs, "taintward.policy.violation") {
		t.Error("policy.violation = false, want true (egress)")
	}
	if !boolAttr(attrs, "taintward.policy.transfer_violation") {
		t.Error("policy.transfer_violation = false, want true (PII -> us)")
	}
	if !boolAttr(attrs, "taintward.policy.redacted") {
		t.Error("policy.redacted = false, want true")
	}
	if r := strAttr(attrs, "taintward.policy.reasons"); r != "transfer,pii_egress" && r != "pii_egress,transfer" {
		t.Errorf("policy.reasons = %q, want transfer+pii_egress", r)
	}
	// Redaction: raw PII must be gone, masked tokens present.
	res := strAttr(attrs, "gen_ai.tool.call.result")
	if res == "" {
		t.Fatal("result attr missing")
	}
	if strings.Contains(res, "234-12-1234") || strings.Contains(res, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("raw PII not redacted: %q", res)
	}
	if !strings.Contains(res, "[PII]") || !strings.Contains(res, "[SECRET]") {
		t.Errorf("masked tokens missing: %q", res)
	}
}

func TestProcessor_InternalSinkNoViolation(t *testing.T) {
	s := &sink{}
	p, _ := newProcessor(&Config{}, s)
	td := ptrace.NewTraces()
	span := newSpan(td, "query_db")
	span.Attributes().PutBool("taintward.sensitive", true)
	span.Attributes().PutStr("taintward.taint.classes", "pii")
	span.Attributes().PutStr("taintward.destination", "internal")

	_ = p.ConsumeTraces(context.Background(), td)
	attrs := s.got.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
	if boolAttr(attrs, "taintward.policy.violation") {
		t.Error("internal sink should not be a violation")
	}
	if !boolAttr(attrs, "taintward.policy.redacted") {
		t.Error("internal sensitive span should still be redacted for storage")
	}
}

func TestProcessor_CleanSpanUntouched(t *testing.T) {
	s := &sink{}
	p, _ := newProcessor(&Config{}, s)
	td := ptrace.NewTraces()
	span := newSpan(td, "agent.decide") // no taintward.* attrs -> not sensitive
	span.Attributes().PutStr("gen_ai.tool.call.result", "nothing sensitive here")

	_ = p.ConsumeTraces(context.Background(), td)
	attrs := s.got.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
	if boolAttr(attrs, "taintward.policy.violation") || boolAttr(attrs, "taintward.policy.redacted") {
		t.Error("clean span should have no policy decision")
	}
	if strAttr(attrs, "gen_ai.tool.call.result") != "nothing sensitive here" {
		t.Error("clean span result was modified")
	}
}
