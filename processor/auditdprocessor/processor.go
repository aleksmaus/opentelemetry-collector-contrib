// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor/internal/logs"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	reassembler, err := NewSyncReassember(5, 2*time.Second, cfg)
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

var (
	ErrAuditFieldNotFound         = errors.New("audit field not found")
	ErrAuditFieldInvalidType      = errors.New("audit field invalid type")
	ErrAuditFieldInvalidTimestamp = errors.New("audit field invalid timestamp")
)

func readAuditFieldStr(body map[string]interface{}, key string) (string, error) {
	v, ok := body[key]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrAuditFieldNotFound, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrAuditFieldInvalidType, key)
	}
	return s, nil
}

func auditMessageFromJournalDBody(body map[string]interface{}) (*auparse.AuditMessage, error) {

	auditTypeStr, err := readAuditFieldStr(body, "_AUDIT_TYPE_NAME")
	if err != nil {
		return nil, err
	}

	var auditType auparse.AuditMessageType
	err = auditType.UnmarshalText([]byte(auditTypeStr))
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit type %s: %w", auditTypeStr, err)
	}

	timestampStr, err := readAuditFieldStr(body, "_SOURCE_REALTIME_TIMESTAMP")
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit timestamp %s: %w", auditTypeStr, err)
	}

	secs := n / 1_000_000
	msec := (n - secs*1_000_000)
	sourceTimestamp := time.Unix(secs, msec*1_000).UTC()

	auditIDStr, err := readAuditFieldStr(body, "_AUDIT_ID")
	if err != nil {
		return nil, err
	}

	sequence, err := strconv.ParseUint(auditIDStr, 10, 32)
	if err != nil {
		return nil, err
	}

	messageStr, err := readAuditFieldStr(body, "MESSAGE")
	if err != nil {
		return nil, err
	}

	msg := &auparse.AuditMessage{
		RecordType: auditType,
		Timestamp:  sourceTimestamp,
		Sequence:   uint32(sequence),
		RawData:    fmt.Sprintf("type=%s msg=audit(%d.%d:%v): %s", auditTypeStr, secs, msec/1000, sequence, strings.TrimSpace(messageStr[len(auditTypeStr):])), // render the full log message to match what's collected with auditd integration
	}

	return msg, nil
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

				var (
					auditMsg *auparse.AuditMessage
					err      error
				)

				body := logRecord.Body()
				// If Body is a parsed key value (from journald) then try to create auparse.AuditMessage from there
				if body.Type() == pcommon.ValueTypeMap {
					auditMsg, err = auditMessageFromJournalDBody(body.Map().AsRaw())
				} else {
					msg := body.AsString()
					auditMsg, err = auparse.ParseLogLine(msg)
					if err != nil {
						p.logger.Error("failed processing logs", zap.Error(err))
						return ld, err
					}
				}

				// Losing original logRecord Attributes here
				// Not exactly sure at the moment what to do with them if we are
				// collapsing multiple log records into fewer number of records with
				// coalesced events
				evres := p.reassembler.PushMessage(auditMsg)

				for _, evr := range evres {
					if evr.Err != nil {
						p.logger.Error("failed to coalesce messages: %v", zap.Error(err))
						continue // ?
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
					err = json.Unmarshal(b, &m)
					if err != nil {
						p.logger.Error("failed marshalling event to map", zap.Error(err))
						return ld, err
					}

					err = logRecord.Body().FromRaw(m)
					if err != nil {
						p.logger.Error("failed logRecord.Body().FromRaw(m)", zap.Error(err))
						return ld, err
					}

					resm := transform(m, logRecord.Attributes().AsRaw(), evr.RawMessages)

					err = logRecord.Attributes().FromRaw(resm)
					if err != nil {
						p.logger.Error("failed logRecord.Attributes().FromRaw", zap.Error(err))
						return ld, err
					}
					if len(evr.RawMessages) > 0 {
						for _, rm := range evr.RawMessages {
							logRecord.Attributes().PutEmptySlice("event.original").AppendEmpty().SetStr(rm)
						}
					}
				}
			}
		}
	}

	return ld, nil
}

func copyAttr(src map[string]any, srcKey string, dst map[string]any, dstKeyOpt ...string) {
	var dstKey string
	if len(dstKeyOpt) == 0 {
		dstKey = srcKey
	} else {
		dstKey = dstKeyOpt[0]
	}

	if v, ok := src[srcKey]; ok {
		dst[dstKey] = v
	}
}

func createOrSetMap(dst map[string]any, key string) map[string]any {
	if v, ok := dst[key]; !ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	m := make(map[string]any)
	dst[key] = m
	return m
}

// transform
func transform(m, attr map[string]any, rawMessages []string) map[string]any {
	am := createOrSetMap(attr, "auditd")
	copyAttr(m, "data", am)

	copyAttr(m, "record_type", am, "message_type")

	copyAttr(m, "result", am)
	copyAttr(m, "session", am)
	copyAttr(m, "summary", am)

	copyAttr(m, "user", am)

	adjustUser(am)

	createUserRelated(m, attr)

	// Set event attributes
	evm := make(map[string]any)
	if v, ok := m["ecs"]; ok {
		if ecsm, ok := v.(map[string]any); ok {
			if v, ok := ecsm["event"]; ok {
				if em, ok := v.(map[string]any); ok {
					copyAttr(em, "category", evm)
					copyAttr(em, "type", evm)
				}
			}
			copyAttr(ecsm, "user", attr)
		}
	}
	evm["kind"] = "event"
	if v, ok := m["summary"]; ok {
		if sm, ok := v.(map[string]any); ok {
			copyAttr(sm, "action", evm)
		}
	}
	copyAttr(m, "sequence", evm)
	copyAttr(m, "result", evm, "outcome")

	if len(rawMessages) != 0 {
		evm["original"] = strings.Join(rawMessages, " ")
	}

	attr["event"] = evm

	copyAttr(m, "process", attr)
	adjustProcess(attr)

	return attr
}

func adjustProcess(m map[string]any) {
	v, ok := m["process"]
	if !ok {
		return
	}

	pm, ok := v.(map[string]any)
	if !ok {
		return
	}

	if v, ok := pm["exe"]; ok {
		delete(pm, "exe")
		pm["executable"] = v
	}

	if v, ok := pm["pid"]; ok {
		s, ok := v.(string)
		if !ok {
			return
		}
		if npid, err := strconv.Atoi(s); err == nil {
			pm["pid"] = npid
		}
	}
}

func adjustUser(m map[string]any) {
	v, ok := m["user"]
	if !ok {
		return
	}

	um, ok := v.(map[string]any)
	if !ok {
		return
	}

	v, ok = um["ids"]
	if !ok {
		return
	}

	idm, ok := v.(map[string]any)
	if !ok {
		return
	}

	v, ok = um["names"]
	if !ok {
		return
	}

	namesm, ok := v.(map[string]any)
	if !ok {
		return
	}

	delete(um, "ids")
	delete(um, "names")

	for k, s := range idm {
		if k == "auid" {
			um["audit"] = map[string]any{"id": s, "name": namesm[k]}
		}
	}
}

func createUserRelated(m, attr map[string]any) {
	v, ok := m["ecs"]
	if !ok {
		return
	}
	ecsm, ok := v.(map[string]any)
	if !ok {
		return
	}

	v, ok = ecsm["user"]
	if !ok {
		return
	}

	um, ok := v.(map[string]any)
	if !ok {
		return
	}

	relm := make(map[string]any)
	u := make([]any, 0, 1)

	if nv, ok := um["name"]; ok {
		u = append(u, nv)
	}

	for k, v := range um {
		if k == "id" || k == "name" {
			continue
		}
		if vm, ok := v.(map[string]any); ok {
			if nv, ok := vm["name"]; ok {
				u = append(u, nv)
			}
		}
	}
	relm["user"] = u
	attr["related"] = relm
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
