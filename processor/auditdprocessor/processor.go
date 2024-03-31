// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor/internal/logs"

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"

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
}

func NewProcessor(cfg Config, settings component.TelemetrySettings) (*Processor, error) {

	return &Processor{
		cfg:    cfg,
		logger: settings.Logger,
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
	resourceLogsSlice := ld.ResourceLogs()
	for i := 0; i < resourceLogsSlice.Len(); i++ {
		resourceLogs := resourceLogsSlice.At(i)
		scopeLogsSlice := resourceLogs.ScopeLogs()
		for i := 0; i < scopeLogsSlice.Len(); i++ {
			scopeLogs := scopeLogsSlice.At(i)
			logRecordSlice := scopeLogs.LogRecords()
			for i := 0; i < logRecordSlice.Len(); i++ {
				logRecord := logRecordSlice.At(i)
				msg := logRecord.Body().AsString()
				auditMsg, err := auparse.ParseLogLine(msg)
				if err != nil {
					p.logger.Error("failed processing logs", zap.Error(err))
					return ld, err
				}

				// TODO: combine related messages

				// TODO: improve errors messages below

				msgs := []*auparse.AuditMessage{auditMsg}

				event, err := aucoalesce.CoalesceMessages(msgs)
				if err != nil {
					log.Printf("failed to coalesce messages: %v", err)
					return ld, err
				}

				if p.cfg.ResolveIDs {
					aucoalesce.ResolveIDs(event)
				}

				// Set timestamp from log msg
				logRecord.SetTimestamp(pcommon.NewTimestampFromTime(auditMsg.Timestamp))

				// The following breaks on map key that has value []string
				// In this particular case, for example: "tags": ["aarch64"]
				// The underlying go-libaudit library adds this to the message
				// Remove tags from the auditMsg.ToMapStr()
				auditMsgMap := auditMsg.ToMapStr()

				if vtags, ok := auditMsgMap["tags"]; ok {
					if tags, ok := vtags.([]string); ok && len(tags) > 0 {
						tagsSlice := logRecord.Attributes().PutEmptySlice("tags")
						for _, tag := range tags {
							tagsSlice.AppendEmpty().SetStr(tag)
						}
					}
				}
				delete(auditMsgMap, "tags")

				// Delete @timestamp property it is already set on logRecord above
				delete(auditMsgMap, "@timestamp")

				// TODO: delete raw_msg
				delete(auditMsgMap, "raw_msg")

				auditMsgMap["sequence"] = auditMsg.Sequence

				m := pcommon.NewMap()
				err = m.FromRaw(auditMsgMap)
				if err != nil {
					return ld, err
				}
				m.CopyTo(logRecord.Attributes().PutEmptyMap("auditd").PutEmptyMap("log"))
				m.CopyTo(logRecord.Body().SetEmptyMap())

				// Set process attributes
				setProcess(&logRecord, auditMsgMap, event)

				// TODO: log.offset is missing
				// "offset": 1757629

				// Set user attributes
				setUser(&logRecord, event)

				// Set event attributes
				setEvent(&logRecord, auditMsgMap, event)
			}
		}
	}

	return ld, nil
}

func setProcess(logRecord *plog.LogRecord, logMsgMap map[string]any, event *aucoalesce.Event) {
	attrs := logRecord.Attributes()
	putIntFromStr(attrs, "process.pid", event.Process.PID)
	putIntFromStr(attrs, "process.parent.pid", event.Process.PPID)

	if event.Process.Name != "" {
		attrs.PutStr("process.name", event.Process.Name)
	}

	// "exit" code was not parsed into event
	if v, ok := logMsgMap["exit"]; ok {
		if s, ok := v.(string); ok {
			attrs.PutStr("process.exit_code", s)
		}
	}

	if event.Process.Exe != "" {
		attrs.PutStr("process.executable", event.Process.Exe)
	}
	if event.Process.CWD != "" {
		attrs.PutStr("process.working_directory", event.Process.CWD)
	}
	if len(event.Process.Args) > 0 {
		attrs.PutInt("process.args_count", int64(len(event.Process.Args)))
		args := attrs.PutEmptySlice("process.args")
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
