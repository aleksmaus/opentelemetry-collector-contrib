// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor"

import (
	"go.opentelemetry.io/collector/component"
)

// Config defines the configuration for the processor.
type Config struct {
	ResolveIDs bool `mapstructure:"resolve_ids"` // If true resolve user/group ids into names
}

var _ component.Config = (*Config)(nil)

func (c *Config) Validate() error {
	return nil
}
