package taintpolicy

import "go.opentelemetry.io/collector/component"

// Config for the taint_policy processor.
//
//	policy_path: optional override to load pii_egress.rego from disk at
//	startup (enables "edit rules without rebuild"). When empty, the
//	embedded policy is used.
//
//	decision_cache_size: how many distinct policy inputs to remember
//	(default 4096). The policy input is five short strings, so real
//	traffic has few distinct values. Set 0 to evaluate Rego on every span,
//	which you need only if a custom policy is not a pure function of its
//	input (for example it calls time.now_ns or http.send).
//
//	drop_attributes: span attributes removed before export. A name ending
//	in "*" is a prefix. The default drops the attributes Google ADK writes
//	on its own spans with the model request, the model response and tool
//	arguments and results: ADK writes them after Taintward restored the
//	placeholders, so they hold real values. Set [] to keep them.
//
//	trusted_services: service.name values whose spans are trusted (gap G7).
//	Empty (the default) trusts every producer, as before. When set, a span
//	from any other service is treated as sensitive whatever its
//	taintward.sensitive says, its taintward.args_redacted marker is ignored
//	(the backstop masks its arguments), and it gets
//	taintward.policy.untrusted_producer=true. Pair it with producer auth
//	(bearertokenauth on the receiver), since service.name is set by the
//	producer.
type Config struct {
	PolicyPath        string   `mapstructure:"policy_path,omitempty"`
	DecisionCacheSize int      `mapstructure:"decision_cache_size"`
	DropAttributes    []string `mapstructure:"drop_attributes"`
	TrustedServices   []string `mapstructure:"trusted_services"`
}

const defaultDecisionCacheSize = 4096

// adkContentAttrs: Google ADK span attributes that carry request, response
// and tool content (ADK 1.14). ADK's ids (event, invocation, session) stay.
var adkContentAttrs = []string{
	"gcp.vertex.agent.llm_request",
	"gcp.vertex.agent.llm_response",
	"gcp.vertex.agent.tool_call_args",
	"gcp.vertex.agent.tool_response",
	"gcp.vertex.agent.data",
}

func createDefaultConfig() component.Config {
	return &Config{
		DecisionCacheSize: defaultDecisionCacheSize,
		DropAttributes:    append([]string(nil), adkContentAttrs...),
	}
}

var _ component.Config = (*Config)(nil)
