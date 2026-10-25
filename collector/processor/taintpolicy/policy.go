package taintpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

const (
	policyPackage = "data.agentward"
	policyQuery   = "data.agentward.decision"
)

// requiredRules must be defined by any policy the processor loads. `decision`
// is what we query; `redact` must exist (with a default) so that `decision`
// is defined for every input.
var requiredRules = []string{"decision", "redact"}

// policyInput is the normalized per-span input. It is also the cache key.
type policyInput struct {
	sensitive    bool
	classes      string
	destination  string
	jurisdiction string
	tool         string
}

func (in policyInput) toMap() map[string]interface{} {
	return map[string]interface{}{
		"sensitive":    in.sensitive,
		"classes":      in.classes,
		"destination":  in.destination,
		"jurisdiction": in.jurisdiction,
		"tool":         in.tool,
	}
}

// decision is the parsed policy output, with the span attribute strings
// precomputed so a cached decision costs no allocations per span.
type decision struct {
	redact       bool
	anyViolation bool
	anyTransfer  bool
	violJSON     string
	reasons      string
}

var errUndefined = errors.New("policy decision is undefined (does the policy define data.agentward.decision with a default for redact?)")

type policy struct {
	prepared rego.PreparedEvalQuery

	cacheMax int
	mu       sync.RWMutex
	cache    map[policyInput]decision
}

// loadPolicy parses, checks, compiles and probes the policy. Any problem is
// a startup error: a policy that silently decides nothing is worse than a
// collector that refuses to start.
func loadPolicy(src string, cacheMax int) (*policy, error) {
	mod, err := ast.ParseModule("pii_egress.rego", src)
	if err != nil {
		return nil, fmt.Errorf("taint_policy: parse rego: %w", err)
	}
	if got := mod.Package.Path.String(); got != policyPackage {
		return nil, fmt.Errorf("taint_policy: policy package is %q, want %q (package agentward)", strings.TrimPrefix(got, "data."), "agentward")
	}
	defined := map[string]bool{}
	for _, r := range mod.Rules {
		if ref := r.Head.Ref(); len(ref) > 0 {
			defined[strings.Trim(ref[0].String(), `"`)] = true
		}
	}
	for _, name := range requiredRules {
		if !defined[name] {
			return nil, fmt.Errorf("taint_policy: policy does not define required rule %q", name)
		}
	}

	prepared, err := rego.New(
		rego.Query(policyQuery),
		rego.Module("pii_egress.rego", src),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("taint_policy: compile rego: %w", err)
	}
	p := &policy{prepared: prepared, cacheMax: cacheMax}
	if cacheMax > 0 {
		p.cache = make(map[policyInput]decision)
	}

	// Probe: the decision must be well formed both for an empty span and for
	// a sensitive egress span.
	probes := []policyInput{
		{},
		{sensitive: true, classes: "pii", destination: "external", jurisdiction: "us"},
	}
	for _, in := range probes {
		if _, err := p.eval(context.Background(), in); err != nil {
			return nil, fmt.Errorf("taint_policy: policy probe failed: %w", err)
		}
	}
	return p, nil
}

// decide returns the policy decision for in, from the cache when possible.
// The cache assumes the policy is a pure function of its input (no
// time.now_ns, http.send, etc.); set decision_cache_size: 0 otherwise.
func (p *policy) decide(ctx context.Context, in policyInput) (decision, error) {
	if p.cache == nil {
		return p.eval(ctx, in)
	}
	p.mu.RLock()
	d, ok := p.cache[in]
	p.mu.RUnlock()
	if ok {
		return d, nil
	}
	d, err := p.eval(ctx, in)
	if err != nil {
		return d, err // errors are never cached
	}
	p.mu.Lock()
	if len(p.cache) >= p.cacheMax {
		clear(p.cache)
	}
	p.cache[in] = d
	p.mu.Unlock()
	return d, nil
}

func (p *policy) eval(ctx context.Context, in policyInput) (decision, error) {
	results, err := p.prepared.Eval(ctx, rego.EvalInput(in.toMap()))
	if err != nil {
		return decision{}, fmt.Errorf("rego eval: %w", err)
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return decision{}, errUndefined
	}
	dm, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return decision{}, fmt.Errorf("policy decision is %T, want an object", results[0].Expressions[0].Value)
	}
	redact, ok := dm["redact"].(bool)
	if !ok {
		return decision{}, fmt.Errorf("policy decision.redact is %T, want bool", dm["redact"])
	}
	violations, ok := dm["violations"].([]interface{})
	if !ok {
		return decision{}, fmt.Errorf("policy decision.violations is %T, want a set or array", dm["violations"])
	}

	d := decision{redact: redact}
	var reasons []string
	for _, v := range violations {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		d.anyViolation = true
		rule, _ := m["rule"].(string)
		reasons = append(reasons, rule)
		if rule == "transfer" {
			d.anyTransfer = true
		}
	}
	vj, err := json.Marshal(violations)
	if err != nil {
		return decision{}, fmt.Errorf("marshal violations: %w", err)
	}
	// Violation records echo input values (sink, jurisdiction); run them
	// through the backstop too.
	d.violJSON, _ = maskString(string(vj))
	d.reasons = strings.Join(reasons, ",")
	return d, nil
}
