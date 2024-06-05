// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reassembler

import (
	"bufio"
	"os"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/stretchr/testify/assert"
)

func TestReassembler(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		testReassembler(t, "testdata/normal.log", &results{
			dropped: 0,
			events: []eventMeta{
				{seq: 58, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("lost_messages", func(t *testing.T) {
		testReassembler(t, "testdata/lost_messages.log", &results{
			dropped: 9,
			events: []eventMeta{
				{seq: 49, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("out_of_order", func(t *testing.T) {
		testReassembler(t, "testdata/out_of_order.log", &results{
			dropped: 0,
			events: []eventMeta{
				{seq: 58, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("rollover", func(t *testing.T) {
		testReassembler(t, "testdata/rollover.log", &results{
			dropped: 0,
			events: []eventMeta{
				{seq: 4294967294, count: 1},
				{seq: 4294967295, count: 1},
				{seq: 0, count: 1},
				{seq: 1, count: 1},
				{seq: 2, count: 1},
			},
		})
	})
}

type eventMeta struct {
	seq   uint
	count int
}

type results struct {
	dropped int
	events  []eventMeta
}

func testReassembler(t testing.TB, file string, expected *results) {
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Inject test event lost handler for testability
	var dropped int
	eventLost := func(count int) {
		dropped += count
	}
	reassembler, err := New(WithMaxInFlight(5), WithTimeout(2*time.Second), WithMaintainInterval(0), WithEventLost(eventLost))
	if err != nil {
		t.Fatal(err)
	}

	// Read logs and parse events.
	var completed [][]*auparse.AuditMessage
	s := bufio.NewScanner(bufio.NewReader(f))
	for s.Scan() {
		line := s.Text()
		msg, err := auparse.ParseLogLine(line)
		if err != nil {
			t.Log("invalid message:", line)
			continue
		}

		completed = append(completed, reassembler.PushMessage(msg)...)
	}

	// Flush any pending messages.
	completed = append(completed, reassembler.Close()...)

	assert.EqualValues(t, expected.dropped, dropped, "dropped messages")
	for i, expectedEvent := range expected.events {
		if len(completed) <= i {
			t.Fatal("less events received than expected")
		}

		for _, msg := range completed[i] {
			assert.EqualValues(t, expectedEvent.seq, msg.Sequence, "sequence number")
		}
		assert.Equal(t, expectedEvent.count, len(completed[i]), "message count")
	}
}
