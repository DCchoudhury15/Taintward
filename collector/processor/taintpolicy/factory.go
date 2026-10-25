package taintpolicy

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
)

// TypeStr is the component type used in collector configs: `taint_policy`.
const TypeStr = "taint_policy"

var stability = component.StabilityLevelDevelopment

// NewFactory returns the processor factory registered with the collector.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(TypeStr),
		createDefaultConfig,
		processor.WithTraces(createTracesProcessor, stability),
	)
}

func createTracesProcessor(
	_ context.Context,
	_ processor.Settings,
	cfg component.Config,
	next consumer.Traces,
) (processor.Traces, error) {
	return newProcessor(cfg.(*Config), next)
}
