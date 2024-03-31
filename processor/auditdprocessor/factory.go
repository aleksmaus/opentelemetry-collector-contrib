// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor/internal/metadata"
)

var processorCapabilities = consumer.Capabilities{MutatesData: true}

func NewFactory() processor.Factory {
	return processor.NewFactory(
		metadata.Type,
		createDefaultConfig,
		processor.WithLogs(createLogsProcessor, metadata.LogsStability),
	)
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func createLogsProcessor(
	ctx context.Context,
	set processor.CreateSettings,
	cfg component.Config,
	nextConsumer consumer.Logs,
) (processor.Logs, error) {
	oCfg := cfg.(*Config)

	proc, err := NewProcessor(*oCfg, set.TelemetrySettings)
	if err != nil {
		return nil, fmt.Errorf("invalid config for \"auditd\" processor %w", err)
	}
	return processorhelper.NewLogsProcessor(
		ctx,
		set,
		cfg,
		nextConsumer,
		proc.ProcessLogs,
		processorhelper.WithCapabilities(processorCapabilities),
		processorhelper.WithStart(proc.Start),
		processorhelper.WithShutdown(proc.Shutdown),
	)
}
