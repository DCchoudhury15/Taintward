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
type Config struct {
	PolicyPath        string `mapstructure:"policy_path,omitempty"`
	DecisionCacheSize int    `mapstructure:"decision_cache_size"`
}

const defaultDecisionCacheSize = 4096

func createDefaultConfig() component.Config {
	return &Config{DecisionCacheSize: defaultDecisionCacheSize}
}

var _ component.Config = (*Config)(nil)
