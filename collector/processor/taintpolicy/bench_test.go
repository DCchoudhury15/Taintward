package taintpolicy

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// benchSpan builds a span shaped like a real SDK tool span.
func benchSpan(withPII bool) ptrace.Span {
	td := ptrace.NewTraces()
	span := newSpan(td, "call_external_api")
	a := span.Attributes()
	a.PutBool("agentward.sensitive", true)
	a.PutStr("agentward.taint.classes", "pii")
	a.PutStr("agentward.destination", "external")
	a.PutStr("agentward.jurisdiction", "us")
	a.PutStr("gen_ai.tool.name", "call_external_api")
	a.PutStr("gen_ai.operation.name", "execute_tool")
	a.PutStr("gen_ai.tool.call.arguments", `{"args":[],"kwargs":{"query":"weekly report for team alpha"}}`)
	if withPII {
		a.PutStr("gen_ai.tool.call.result", `{"name":"Jane","ssn":"234-12-1234","email":"jane@example.com"}`)
	} else {
		a.PutStr("gen_ai.tool.call.result", `{"status":"ok","rows":42,"note":"nothing sensitive in this result at all"}`)
	}
	return span
}

func benchProcessSpan(b *testing.B, cacheSize int, withPII bool) {
	p, err := newProcessor(&Config{DecisionCacheSize: cacheSize}, &sink{})
	if err != nil {
		b.Fatal(err)
	}
	tmpl := benchSpan(withPII)
	work := ptrace.NewSpan()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tmpl.CopyTo(work)
		p.processSpan(ctx, work)
	}
}

// BenchmarkProcessSpan measures one span through policy eval + redaction.
// "clean" has no raw PII in any string; "pii" has an SSN and an email.
// The -nocache variants evaluate Rego on every span.
func BenchmarkProcessSpan(b *testing.B) {
	b.Run("clean", func(b *testing.B) { benchProcessSpan(b, defaultDecisionCacheSize, false) })
	b.Run("pii", func(b *testing.B) { benchProcessSpan(b, defaultDecisionCacheSize, true) })
	b.Run("clean-nocache", func(b *testing.B) { benchProcessSpan(b, 0, false) })
	b.Run("pii-nocache", func(b *testing.B) { benchProcessSpan(b, 0, true) })
}
