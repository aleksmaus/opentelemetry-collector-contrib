// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reassembler

import (
	"fmt"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

// Synchronous version of Reassembler
// Adapter for the Reassembler implemented in
// https://github.com/elastic/go-libaudit/blob/main/reassembler.go
// The callback interface doesn't quite work for the pipeline kind of processing
type Reassembler struct {
	maxInFlight int
	timeout     time.Duration

	maintainInterval   time.Duration
	lastTimeMaintained time.Time

	ra *libaudit.Reassembler

	completed [][]*auparse.AuditMessage

	fnEventsLost func(count int)
}

// Defaults
const (
	defaultMaxInFlight      = 2000
	defaultTimeout          = 5 * time.Second
	defaultMaintainInterval = 0
)

type Option func(*Reassembler)

func New(opts ...Option) (*Reassembler, error) {
	r := &Reassembler{
		maxInFlight:      defaultMaxInFlight,
		timeout:          defaultTimeout,
		maintainInterval: defaultMaintainInterval,
	}

	for _, opt := range opts {
		opt(r)
	}

	ra, err := libaudit.NewReassembler(r.maxInFlight, r.timeout, r)
	if err != nil {
		return nil, err
	}

	r.ra = ra

	return r, nil
}

func WithMaxInFlight(maxInFlight int) Option {
	return func(r *Reassembler) {
		r.maxInFlight = maxInFlight
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(r *Reassembler) {
		r.timeout = timeout
	}
}

func WithMaintainInterval(maintainInterval time.Duration) Option {
	return func(r *Reassembler) {
		r.maintainInterval = maintainInterval
	}
}

func WithEventLost(fn func(count int)) Option {
	return func(r *Reassembler) {
		r.fnEventsLost = fn
	}
}

// Closes reassembler,
func (r *Reassembler) Close() [][]*auparse.AuditMessage {
	// Ignore errReassemblerClosed
	_ = r.ra.Close()

	completed := r.completed
	r.completed = nil

	return completed
}

func (r *Reassembler) PushMessage(msg *auparse.AuditMessage) [][]*auparse.AuditMessage {
	r.ra.PushMessage(msg)

	if r.maintainInterval <= 0 || time.Since(r.lastTimeMaintained) > r.maintainInterval {
		// ignoring the error on Maintain
		fmt.Println("MAINTAIN")
		_ = r.ra.Maintain()
		if r.maintainInterval > 0 {
			r.lastTimeMaintained = time.Now()
		}
	}

	completed := r.completed
	r.completed = nil
	return completed
}

// Reassembler callbacks
func (r *Reassembler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	fmt.Println("ReassemblyComplete: %v", len(msgs))
	if len(msgs) == 0 {
		return
	}
	r.completed = append(r.completed, msgs)
}

func (r *Reassembler) EventsLost(count int) {
	if r.fnEventsLost != nil {
		r.fnEventsLost(count)
	}
}
