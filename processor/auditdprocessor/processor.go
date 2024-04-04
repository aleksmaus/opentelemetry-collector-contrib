// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor/internal/logs"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"

	"go.uber.org/zap"
)

var errProcessorNotRunning = errors.New("auditd processor is not running")

// Auditd log processor is using go-libaudit library https://github.com/elastic/go-libaudit
//
// The Reassember push/callback interface doesn't quite work here, needs to be rewritten
//
// TODO: Rewrite https://github.com/elastic/go-libaudit/blob/main/reassembler.go
type Processor struct {
	cfg    Config
	logger *zap.Logger

	reassembler *SyncReassembler
}

func NewProcessor(cfg Config, settings component.TelemetrySettings) (*Processor, error) {

	//TODO: pass the logger
	reassembler, err := NewSyncReassember(5, 2*time.Second, true)
	if err != nil {
		return nil, err
	}

	return &Processor{
		cfg:         cfg,
		logger:      settings.Logger,
		reassembler: reassembler,
	}, nil
}

func (p *Processor) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (p *Processor) Shutdown(context.Context) error {
	return nil
}

func (p *Processor) ProcessLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	res, err := p.processLogs(ctx, ld)
	if err != nil {
		fmt.Println("ERROR:", err)
	}
	return res, err
}

func (p *Processor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	// I think for auditd is appropriate to reuse the resource and scope for coalesed event messages if they are all coming from the same source I guess
	// Brute force this approach for now and then could try to figure out how to track all the resources/scopes down to coalesced messaages
	resourceLogsSlice := ld.ResourceLogs()
	for i := 0; i < resourceLogsSlice.Len(); i++ {
		resourceLogs := resourceLogsSlice.At(i)

		scopeLogsSlice := resourceLogs.ScopeLogs()
		for i := 0; i < scopeLogsSlice.Len(); i++ {
			scopeLogs := scopeLogsSlice.At(i)

			oldScopeLogs := plog.NewScopeLogs()
			// TODO: There might be more efficient way to do this.
			scopeLogs.MoveTo(oldScopeLogs)
			logRecordSlice := oldScopeLogs.LogRecords()

			for i := 0; i < logRecordSlice.Len(); i++ {
				logRecord := logRecordSlice.At(i)

				msg := logRecord.Body().AsString()
				auditMsg, err := auparse.ParseLogLine(msg)
				if err != nil {
					p.logger.Error("failed processing logs", zap.Error(err))
					return ld, err
				}

				// Loosing original logRecord Attributes here
				// Not exactly sure at the moment what to do with them if we are
				// collapsing multiple log records into fewer number of records with
				// coalesced events
				evres := p.reassembler.PushMessage(auditMsg)

				for _, evr := range evres {
					if evr.Err != nil {
						p.logger.Error("failed to coalesce messages: %v", zap.Error(err))
						return ld, err
					}
					event := evr.Event

					logRecord := scopeLogs.LogRecords().AppendEmpty()

					// Set timestamp from log msg
					logRecord.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))

					// Set structured body from event JSON
					// The only way it seems is to marshal event into JSON
					// then unmarshal into map[string]any
					// not effecient
					b, _ := json.Marshal(event)
					var m map[string]any
					_ = json.Unmarshal(b, &m)
					err = logRecord.Body().FromRaw(m)
					if err != nil {
						fmt.Println("FAILED logRecord.Body().FromRaw(m):", err)
					}

					attr := logRecord.Attributes()

					// Populate "auditd.log" from data
					if data, ok := m["data"]; ok {
						logMap := attr.PutEmptyMap("auditd").PutEmptyMap("log")
						mdata, ok := data.(map[string]any)
						if ok {
							dataMap := pcommon.NewMap()
							_ = dataMap.FromRaw(mdata)
							dataMap.CopyTo(logMap)
						}
						logMap.PutInt("sequence", int64(event.Sequence))
					}

					// Populate tags
					if vtags, ok := m["tags"]; ok {
						if tags, ok := vtags.([]string); ok && len(tags) > 0 {
							tagsSlice := attr.PutEmptySlice("tags")
							for _, tag := range tags {
								tagsSlice.AppendEmpty().SetStr(tag)
							}
						}
					}

					// // Set process attributes
					setProcess(attr, event)

					// // TODO: log.offset is missing, not sure if possible to get yet
					// // "offset": 1757629

					// Set ECS attributes
					if ecs, ok := m["ecs"]; ok {
						mecs, ok := ecs.(map[string]any)
						if ok {
							ecsMap := pcommon.NewMap()
							_ = ecsMap.FromRaw(mecs)
							ecsMap.Range(func(k string, v pcommon.Value) bool {
								tv := attr.PutEmpty(k)
								v.CopyTo(tv)
								if k == "event" {
									// Set event action
									if event.Summary.Action != "" {
										attr.PutStr("event.action", event.Summary.Action)
									}
								}
								return true
							})
						}
					}
				}

			}
		}
	}

	return ld, nil
}

func setProcess(attr pcommon.Map, event *aucoalesce.Event) {
	putIntFromStr(attr, "process.pid", event.Process.PID)
	putIntFromStr(attr, "process.parent.pid", event.Process.PPID)

	if event.Process.Name != "" {
		attr.PutStr("process.name", event.Process.Name)
	}

	// "exit" code was not parsed into event
	if s, ok := event.Data["exit"]; ok {
		attr.PutStr("process.exit_code", s)
	}

	if event.Process.Exe != "" {
		attr.PutStr("process.executable", event.Process.Exe)
	}
	if event.Process.CWD != "" {
		attr.PutStr("process.working_directory", event.Process.CWD)
	}
	if len(event.Process.Args) > 0 {
		attr.PutInt("process.args_count", int64(len(event.Process.Args)))
		args := attr.PutEmptySlice("process.args")
		for _, arg := range event.Process.Args {
			args.AppendEmpty().SetStr(arg)
		}
	}

}

func setUserField(attrs *pcommon.Map, m map[string]string, src string, dst string) {
	if v, ok := m[src]; ok {
		attrs.PutStr(dst, v)
	}
}

func setUser(logRecord *plog.LogRecord, event *aucoalesce.Event) {
	attrs := logRecord.Attributes()

	if len(event.User.IDs) == 0 {
		return
	}

	setUserField(&attrs, event.User.IDs, "uid", "user.id")
	setUserField(&attrs, event.User.IDs, "gid", "user.group.id")

	setUserField(&attrs, event.User.IDs, "auid", "user.audit.id")
	setUserField(&attrs, event.User.IDs, "agid", "user.audit.group.id")

	setUserField(&attrs, event.User.IDs, "euid", "user.effective.id")
	setUserField(&attrs, event.User.IDs, "egid", "user.effective.group.id")

	setUserField(&attrs, event.User.IDs, "fsuid", "user.filesystem.id")
	setUserField(&attrs, event.User.IDs, "fsgid", "user.filesystem.group.id")

	setUserField(&attrs, event.User.IDs, "suid", "user.saved.id")
	setUserField(&attrs, event.User.IDs, "sgid", "user.saved.group.id")

	// Names resolution
	if len(event.User.Names) == 0 {
		return
	}
	setUserField(&attrs, event.User.Names, "uid", "user.name")
	setUserField(&attrs, event.User.Names, "gid", "user.group.name")

	setUserField(&attrs, event.User.Names, "auid", "user.audit.name")
	setUserField(&attrs, event.User.Names, "agid", "user.audit.group.name")

	setUserField(&attrs, event.User.Names, "euid", "user.effective.name")
	setUserField(&attrs, event.User.Names, "egid", "user.effective.group.name")

	setUserField(&attrs, event.User.Names, "fsuid", "user.filesystem.name")
	setUserField(&attrs, event.User.Names, "fsgid", "user.filesystem.group.name")

	setUserField(&attrs, event.User.Names, "suid", "user.saved.name")
	setUserField(&attrs, event.User.Names, "sgid", "user.saved.group.name")
}

func setEvent(logRecord *plog.LogRecord, logMsgMap map[string]any, event *aucoalesce.Event) {
	attrs := logRecord.Attributes()
	attrs.PutStr("event.kind", "event")

	attrs.PutStr("event.type", event.Type.String())
	attrs.PutStr("event.category", event.Category.String())
	attrs.PutStr("event.action", event.Summary.Action)
}

func putIntFromStr(m pcommon.Map, key, val string) {
	n := intFromStr(val)
	if n != 0 {
		m.PutInt(key, n)
	}
}

func intFromStr(val string) int64 {
	n, _ := strconv.ParseInt(val, 10, 64)
	return n
}

// Callbacks for reassembler

// ReassemblyComplete notifies that a complete group of events has been
// received and provides those events.
func (p *Processor) ReassemblyComplete(msgs []*auparse.AuditMessage) {
}

// EventsLost notifies that some events were lost. This is based on gaps
// in the sequence numbers of received messages. Lost events can be caused
// by a slow receiver or because the kernel is configured to rate limit
// events.
func (p *Processor) EventsLost(count int) {
}
