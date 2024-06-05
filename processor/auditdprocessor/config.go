// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor"

import "time" // Config defines the configuration for the auditd processor.
type Config struct {
	MaxInFlight int           `mapstructure:"max_inflight"` // Max number of events (based on timestamp + sequence) that are buffered.
	Timeout     time.Duration `mapstructure:"timeout"`      // Timeout controls how long the Reassembler waits for an EOE message (end-of-event)

	ResolveIDs            bool `mapstructure:"resolve_ids"`             // If true resolve user/group ids into names
	PreserveOriginalEvent bool `mapstructure:"preserve_original_event"` // If true preserve the original messages
}

func (cfg *Config) Validate() error {
	return nil
}
