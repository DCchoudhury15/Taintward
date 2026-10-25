package taintpolicy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
)

// These tests cover config.go / factory.go: does a bad policy_path or a
// syntactically invalid Rego file fail loudly at collector startup (via
// component construction), rather than silently misbehaving at runtime?

func TestConfig_DefaultUsesEmbeddedPolicy(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	if cfg.PolicyPath != "" {
		t.Fatalf("default PolicyPath = %q, want empty (embedded policy)", cfg.PolicyPath)
	}
	if _, err := newProcessor(cfg, &sink{}); err != nil {
		t.Fatalf("newProcessor with default config (embedded policy) failed: %v", err)
	}
}

func TestConfig_NonexistentPolicyPathFailsAtConstruction(t *testing.T) {
	_, err := newProcessor(&Config{PolicyPath: "/nonexistent/does-not-exist.rego"}, &sink{})
	if err == nil {
		t.Fatal("expected an error constructing the processor with a nonexistent policy_path, got nil")
	}
}

func TestConfig_MalformedRegoFailsAtConstruction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.rego")
	if err := os.WriteFile(path, []byte("package taintward\n\ndecision := {\n"), 0o644); err != nil {
		t.Fatalf("writing temp rego file: %v", err)
	}
	_, err := newProcessor(&Config{PolicyPath: path}, &sink{})
	if err == nil {
		t.Fatal("expected an error constructing the processor with a malformed Rego policy, got nil")
	}
}

// TestFactory_CreateTracesProcessorForwardsNextConsumer guards against the
// pipeline-stall class of bug: processor.CreateTracesFunc in collector
// v1.66.0 takes `next consumer.Traces` as its 4th arg, and it MUST be the
// consumer the built processor forwards spans to.
func TestFactory_CreateTracesProcessorForwardsNextConsumer(t *testing.T) {
	f := NewFactory()
	s := &sink{}
	p, err := f.CreateTraces(
		context.Background(),
		processor.Settings{ID: component.NewID(component.MustNewType(TypeStr))},
		f.CreateDefaultConfig(),
		s,
	)
	if err != nil {
		t.Fatalf("CreateTraces: %v", err)
	}

	td := ptrace.NewTraces()
	newSpan(td, "factory_smoke_span")
	if err := p.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if s.got.ResourceSpans().Len() != td.ResourceSpans().Len() {
		t.Fatal("factory-built processor did not forward traces to the `next` consumer passed to CreateTraces")
	}
}

func TestFactory_CapabilitiesLivesInConsumerPackage(t *testing.T) {
	f := NewFactory()
	p, err := f.CreateTraces(
		context.Background(),
		processor.Settings{ID: component.NewID(component.MustNewType(TypeStr))},
		f.CreateDefaultConfig(),
		&sink{},
	)
	if err != nil {
		t.Fatalf("CreateTraces: %v", err)
	}
	var _ consumer.Capabilities = p.Capabilities()
	if !p.Capabilities().MutatesData {
		t.Error("Capabilities().MutatesData = false, want true (processor redacts span attrs in place)")
	}
}
