package taintpolicy

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
)

//go:embed pii_egress.rego
var embeddedPolicy string

// Attributes read off each span to feed the Rego policy.
const (
	attSensitive    = "taintward.sensitive"
	attClasses      = "taintward.taint.classes"
	attDestination  = "taintward.destination"
	attJurisdiction = "taintward.jurisdiction"
	attTool         = "gen_ai.tool.name"

	// attArgs holds the tool call arguments. The SDK may store them as
	// reversible format-preserving tokens, which look like PII to the
	// regexes; the backstop leaves this one attribute alone ONLY when the
	// span carries attArgsRedacted=true (bool).
	attArgs         = "gen_ai.tool.call.arguments"
	attArgsRedacted = "taintward.args_redacted"
)

// Attributes written by the collector (authoritative: Rego is the source of truth).
const (
	attPolicyPrefix     = "taintward.policy."
	attPolicyRedact     = "taintward.policy.redacted"
	attPolicyViolation  = "taintward.policy.violation"
	attPolicyTransfer   = "taintward.policy.transfer_violation"
	attPolicyViolations = "taintward.policy.violations"
	attPolicyReasons    = "taintward.policy.reasons"
	attPolicyDecision   = "taintward.policy.decision_engine"
	attPolicyError      = "taintward.policy.error"
	attPolicyMasked     = "taintward.policy.masked_values"
	attPolicyDropped    = "taintward.policy.dropped_attributes"
	attPolicyUntrusted  = "taintward.policy.untrusted_producer"
	attServiceName      = "service.name"
	decisionEngine      = "rego"
)

// ownedAttrs are the attributes only the collector may write.
var ownedAttrs = map[string]struct{}{
	attPolicyRedact: {}, attPolicyViolation: {}, attPolicyTransfer: {},
	attPolicyViolations: {}, attPolicyReasons: {}, attPolicyDecision: {},
	attPolicyError: {}, attPolicyMasked: {}, attPolicyDropped: {}, attPolicyUntrusted: {},
}

// taintPolicyProcessor is a traces processor that:
//  1. reads taintward.* attrs off each span,
//  2. evaluates the Rego policy (compile once, eval many, cached),
//  3. writes collector-authoritative taintward.policy.* attrs, and
//  4. runs the regex backstop over every string the span carries (attrs,
//     nested values, name, status, events, links, resource and scope attrs)
//     so the backend never stores a raw secret or PII pattern.
//
// It fails closed: a policy error or undefined decision still redacts and
// records taintward.policy.error.
type taintPolicyProcessor struct {
	cfg     *Config
	next    consumer.Traces
	policy  *policy
	drop    attrMatcher
	trusted map[string]struct{} // empty: every producer is trusted
}

var _ processor.Traces = (*taintPolicyProcessor)(nil)

func newProcessor(cfg *Config, next consumer.Traces) (*taintPolicyProcessor, error) {
	if cfg.DecisionCacheSize < 0 {
		return nil, fmt.Errorf("taint_policy: decision_cache_size must be >= 0, got %d", cfg.DecisionCacheSize)
	}
	policySrc := embeddedPolicy
	if cfg.PolicyPath != "" {
		b, err := os.ReadFile(cfg.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("taint_policy: read policy_path %q: %w", cfg.PolicyPath, err)
		}
		policySrc = string(b)
	}
	pol, err := loadPolicy(policySrc, cfg.DecisionCacheSize)
	if err != nil {
		return nil, err
	}
	trusted := map[string]struct{}{}
	for _, s := range cfg.TrustedServices {
		trusted[s] = struct{}{}
	}
	return &taintPolicyProcessor{cfg: cfg, next: next, policy: pol,
		drop: newAttrMatcher(cfg.DropAttributes), trusted: trusted}, nil
}

// Capabilities: mutates span data.
func (p *taintPolicyProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

// Start / Shutdown satisfy component.Component (no setup/teardown needed).
func (p *taintPolicyProcessor) Start(context.Context, component.Host) error { return nil }
func (p *taintPolicyProcessor) Shutdown(context.Context) error              { return nil }

// ConsumeTraces evaluates the policy on every span, redacts in place, then
// forwards to the next consumer in the pipeline.
func (p *taintPolicyProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)
		// Read before masking: the service name decides trust (gap G7).
		trusted := p.isTrusted(getStr(rs.Resource().Attributes(), attServiceName))
		maskMap(rs.Resource().Attributes(), "", 0)
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			maskMap(ss.Scope().Attributes(), "", 0)
			for k := 0; k < ss.Spans().Len(); k++ {
				p.processSpan(ctx, ss.Spans().At(k), trusted)
			}
		}
	}
	return p.next.ConsumeTraces(ctx, td)
}

func (p *taintPolicyProcessor) isTrusted(service string) bool {
	if len(p.trusted) == 0 {
		return true
	}
	_, ok := p.trusted[service]
	return ok
}

func (p *taintPolicyProcessor) processSpan(ctx context.Context, span ptrace.Span, trusted bool) {
	attrs := span.Attributes()

	// Normalize in Go as well as in the policy, so a custom policy that
	// forgets lower() still sees "us", not "US". An untrusted producer
	// cannot claim its data is clean (gap G7).
	in := policyInput{
		sensitive:    truthy(attrs, attSensitive) || !trusted,
		classes:      lowerStr(attrs, attClasses),
		destination:  lowerStr(attrs, attDestination),
		jurisdiction: lowerStr(attrs, attJurisdiction),
		tool:         getStr(attrs, attTool),
	}
	d, err := p.policy.decide(ctx, in)

	// Drop the attributes this processor owns if the producer already sent
	// them: a fake "violation=false" must not survive a policy error. Other
	// taintward.policy.* keys (the gateway writes taintward.policy.rules)
	// are left alone.
	if hasPrefixKey(attrs, attPolicyPrefix) {
		attrs.RemoveIf(func(k string, _ pcommon.Value) bool {
			_, owned := ownedAttrs[k]
			return owned
		})
	}

	dropped := p.drop.removeFrom(attrs)
	masked := redactSpan(span, trusted)

	if err != nil {
		// Fail closed: the backstop above already ran on everything.
		msg, _ := maskString(err.Error())
		attrs.PutStr(attPolicyError, msg)
		attrs.PutBool(attPolicyRedact, true)
	} else {
		attrs.PutBool(attPolicyRedact, d.redact)
		attrs.PutBool(attPolicyViolation, d.anyViolation)
		attrs.PutBool(attPolicyTransfer, d.anyTransfer)
		attrs.PutStr(attPolicyViolations, d.violJSON)
		attrs.PutStr(attPolicyReasons, d.reasons)
	}
	attrs.PutStr(attPolicyDecision, decisionEngine)
	if masked > 0 {
		attrs.PutInt(attPolicyMasked, int64(masked))
	}
	if dropped > 0 {
		attrs.PutInt(attPolicyDropped, int64(dropped))
	}
	if !trusted {
		attrs.PutBool(attPolicyUntrusted, true)
	}
}

// attrMatcher matches attribute names exactly or, for entries ending in
// "*", by prefix.
type attrMatcher struct {
	names    map[string]struct{}
	prefixes []string
}

func newAttrMatcher(entries []string) attrMatcher {
	m := attrMatcher{names: map[string]struct{}{}}
	for _, e := range entries {
		if p, ok := strings.CutSuffix(e, "*"); ok {
			m.prefixes = append(m.prefixes, p)
		} else if e != "" {
			m.names[e] = struct{}{}
		}
	}
	return m
}

func (m attrMatcher) match(k string) bool {
	if _, ok := m.names[k]; ok {
		return true
	}
	for _, p := range m.prefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// removeFrom drops the matching attributes and returns how many it dropped.
func (m attrMatcher) removeFrom(attrs pcommon.Map) int {
	if len(m.names) == 0 && len(m.prefixes) == 0 {
		return 0
	}
	n := 0
	attrs.RemoveIf(func(k string, _ pcommon.Value) bool {
		if m.match(k) {
			n++
			return true
		}
		return false
	})
	return n
}

// redactSpan runs the backstop over every string on the span and returns
// how many values it masked.
// The args_redacted marker is honored only from a trusted producer.
func redactSpan(span ptrace.Span, trusted bool) int {
	attrs := span.Attributes()
	skip := ""
	if trusted && argsMarked(attrs) {
		skip = attArgs
	}
	n := maskMap(attrs, skip, 0)

	if out, hit := maskString(span.Name()); hit {
		span.SetName(out)
		n++
	}
	if out, hit := maskString(span.Status().Message()); hit {
		span.Status().SetMessage(out)
		n++
	}
	evs := span.Events()
	for i := 0; i < evs.Len(); i++ {
		ev := evs.At(i)
		if out, hit := maskString(ev.Name()); hit {
			ev.SetName(out)
			n++
		}
		n += maskMap(ev.Attributes(), "", 0)
	}
	links := span.Links()
	for i := 0; i < links.Len(); i++ {
		n += maskMap(links.At(i).Attributes(), "", 0)
	}
	return n
}

// --- attribute helpers ---

func getStr(m pcommon.Map, key string) string {
	v, ok := m.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return v.Str()
}

// lowerStr returns the trimmed, lower-cased string attr. strings.ToLower
// and TrimSpace return their input unchanged (no allocation) when there is
// nothing to change.
func lowerStr(m pcommon.Map, key string) string {
	return strings.ToLower(strings.TrimSpace(getStr(m, key)))
}

// truthy accepts bool true, the strings "true" / "1" (any case, trimmed),
// and a non-zero int. Producers other than the Python SDK often stringify
// booleans; reading those as "not sensitive" would mask nothing.
func truthy(m pcommon.Map, key string) bool {
	v, ok := m.Get(key)
	if !ok {
		return false
	}
	switch v.Type() {
	case pcommon.ValueTypeBool:
		return v.Bool()
	case pcommon.ValueTypeStr:
		s := strings.TrimSpace(v.Str())
		return s == "1" || strings.EqualFold(s, "true")
	case pcommon.ValueTypeInt:
		return v.Int() != 0
	}
	return false
}

// argsMarked is strict on purpose (bool true only): this marker turns
// redaction OFF for one attribute, so anything unclear means "redact".
func argsMarked(m pcommon.Map) bool {
	v, ok := m.Get(attArgsRedacted)
	return ok && v.Type() == pcommon.ValueTypeBool && v.Bool()
}

func hasPrefixKey(m pcommon.Map, prefix string) bool {
	found := false
	m.Range(func(k string, _ pcommon.Value) bool {
		if strings.HasPrefix(k, prefix) {
			found = true
			return false
		}
		return true
	})
	return found
}
