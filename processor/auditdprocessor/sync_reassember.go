package auditdprocessor

import (
	"log"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
)

type EventResolution struct {
	Event *aucoalesce.Event
	Err   error
}

type SyncReassembler struct {
	resolveID bool

	reassembler *libaudit.Reassembler
	completed   []EventResolution
}

func NewSyncReassember(maxInFlight int, timeout time.Duration, resolveID bool) (*SyncReassembler, error) {

	r := &SyncReassembler{resolveID: resolveID}

	reassembler, err := libaudit.NewReassembler(maxInFlight, timeout, r)
	if err != nil {
		return nil, err
	}
	r.reassembler = reassembler

	return r, nil
}

func (r *SyncReassembler) Close() error {
	return r.reassembler.Close()
}

func (r *SyncReassembler) PushMessage(msg *auparse.AuditMessage) []EventResolution {
	r.reassembler.PushMessage(msg)

	// "maintaining" on every call, do not care about errReassemblerClosed
	// TODO: can improve "maintenance" interval calling it only
	// when the time since the last call >= maintenance interval
	_ = r.reassembler.Maintain()

	completed := r.completed
	r.completed = nil
	return completed
}

func (r *SyncReassembler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	event, err := r.resolveMessages(msgs)
	if err != nil {
		log.Printf("[WARN] failed writing message to output: %v", err)
	}
	r.completed = append(r.completed, EventResolution{Event: event, Err: err})
}

func (r *SyncReassembler) EventsLost(count int) {
	log.Printf("[WARN] detected the loss of %v sequences.", count)
}

func (r *SyncReassembler) resolveMessages(msgs []*auparse.AuditMessage) (*aucoalesce.Event, error) {
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		return nil, err
	}
	if r.resolveID {
		aucoalesce.ResolveIDs(event)
	}
	return event, nil
}
