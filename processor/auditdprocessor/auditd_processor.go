// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor/internal/reassembler"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type auditdProcessor struct {
	cfg    Config
	logger *zap.Logger

	reassembler *reassembler.Reassembler
}

func newAuditdProcessor(cfg Config, settings component.TelemetrySettings) (*auditdProcessor, error) {
	reassembler, err := reassembler.New()
	if err != nil {
		return nil, err
	}
	return &auditdProcessor{
		cfg:         cfg,
		logger:      settings.Logger,
		reassembler: reassembler,
	}, nil
}

func (p *auditdProcessor) start(_ context.Context, _ component.Host) error {
	return nil
}

func (p *auditdProcessor) shutdown(context.Context) error {
	return nil
}

func (p *auditdProcessor) processLogs(_ context.Context, ls plog.Logs) (plog.Logs, error) {
	resourceLogsSlice := ls.ResourceLogs()

	for i := 0; i < resourceLogsSlice.Len(); i++ {
		resourceLogs := resourceLogsSlice.At(i)

		scopeLogsSlice := resourceLogs.ScopeLogs()

		// Empty the current scopelogs slice
		origScopeLogsSlice := plog.NewScopeLogsSlice()
		scopeLogsSlice.MoveAndAppendTo(origScopeLogsSlice)

		for i := 0; i < origScopeLogsSlice.Len(); i++ {
			scopeLogs := origScopeLogsSlice.At(i)

			// Make a copy of attributes and schema for the messages context payload, without logs
			contextScopeLogs := plog.NewScopeLogs()
			contextScopeLogs.SetSchemaUrl(scopeLogs.SchemaUrl())
			scopeLogs.Scope().CopyTo(contextScopeLogs.Scope())

			logRecordSlice := scopeLogs.LogRecords()

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
					if err != nil {
						p.logger.Error("failed creating log message from journald body", zap.Error(err))
						continue
					}
				} else {
					msg := body.AsString()
					auditMsg, err = auparse.ParseLogLine(msg)
					if err != nil {
						p.logger.Error("failed parsing log message", zap.Error(err))
						continue
					}
				}

				auditMsg.Payload = contextScopeLogs
				fmt.Println("PUSH:", auditMsg.RawData)
				msgsRes := p.reassembler.PushMessage(auditMsg)
				fmt.Println("RES:", msgsRes)

				// Got related messages, now iterate the blocks of messages and coalsce every block into event
				for _, msgs := range msgsRes {
					if len(msgs) == 0 {
						continue
					}

					event, err := p.resolve(msgs)
					if err != nil {
						p.logger.Error("failed to resolve event from messages", zap.Error(err))
						continue
					}

					msgScopeLogs := msgs[0].Payload.(plog.ScopeLogs)

					newScopeLogs := scopeLogsSlice.AppendEmpty()
					msgScopeLogs.CopyTo(newScopeLogs)

					logRecord := newScopeLogs.LogRecords().AppendEmpty()
					logRecord.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))

					// Deserialize event into generic map suitable for log record body
					m, err := eventToMap(event)
					if err != nil {
						p.logger.Error("failed to serialize event into map", zap.Error(err))
						continue
					}

					// Set the body from the serialized event map
					err = logRecord.Body().FromRaw(m)
					if err != nil {
						p.logger.Error("failed to create log body from map", zap.Error(err))
						continue
					}

					// Pupulate OTel attributes
					attrs := p.populateAttributes(m, logRecord.Attributes().AsRaw(), msgs)
					err = logRecord.Attributes().FromRaw(attrs)
					if err != nil {
						p.logger.Error("failed to set log attributes", zap.Error(err))
					}

					// Set auditd.messages directly to attrobites, otherwise FromRaw map fails on slices of strings
					if p.cfg.PreserveOriginalEvent && len(msgs) != 0 {
						aum := logRecord.Attributes().PutEmptySlice("auditd.messages")
						for _, msg := range msgs {
							aum.AppendEmpty().SetStr(msg.RawData)
						}
					}

				}
			}
		}
	}
	return ls, nil
}

func (p *auditdProcessor) resolve(msgs []*auparse.AuditMessage) (*aucoalesce.Event, error) {
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		return nil, err
	}
	if p.cfg.ResolveIDs {
		aucoalesce.ResolveIDs(event)
	}
	return event, nil
}

func eventToMap(event *aucoalesce.Event) (map[string]interface{}, error) {
	// Currently is the only way to convert Event to map
	// Attempted to use mapstructure libary, it was generating some bad fields values, like hex values for some of the enum types
	var m map[string]interface{}

	b, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

var (
	ErrAuditFieldNotFound    = errors.New("audit field not found")
	ErrAuditFieldInvalidType = errors.New("audit field invalid type")
)

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
		RawData:    fmt.Sprintf("type=%s msg=audit(%d.%03d:%v): %s", auditTypeStr, secs, msec/1000, sequence, strings.TrimSpace(messageStr[len(auditTypeStr):])), // render the full log message to match what's collected with auditd integration
	}

	return msg, nil
}

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

func (p *auditdProcessor) populateAttributes(event, attr map[string]interface{}, msgs []*auparse.AuditMessage) map[string]interface{} {
	am := createOrSetMap(attr, "auditd")
	copyAttr(event, "data", am)

	copyAttr(event, "record_type", am, "message_type")

	copyAttr(event, "result", am)
	copyAttr(event, "session", am)
	copyAttr(event, "summary", am)

	copyAttr(event, "user", am)

	createUserRelated(event, attr)

	// Set event attributes
	evm := make(map[string]any)
	if v, ok := event["ecs"]; ok {
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
	if v, ok := event["summary"]; ok {
		if sm, ok := v.(map[string]any); ok {
			copyAttr(sm, "action", evm)
		}
	}
	copyAttr(event, "sequence", evm)
	copyAttr(event, "result", evm, "outcome")

	var original strings.Builder

	if p.cfg.PreserveOriginalEvent {
		for _, msg := range msgs {
			if original.Len() > 0 {
				original.WriteString(" ")
			}
			original.WriteString(msg.RawData)
		}
	}

	if original.Len() != 0 {
		evm["original"] = original.String()
	}

	adjustUser(am, attr)

	attr["event"] = evm

	copyAttr(attr, "process", attr)
	adjustProcess(attr)

	return attr
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

	if v, ok := pm["ppid"]; ok {
		s, ok := v.(string)
		if !ok {
			return
		}
		if npid, err := strconv.Atoi(s); err == nil {
			pm["parent"] = map[string]any{
				"pid": npid,
			}
		}
		delete(pm, "ppid")
	}
}

func adjustUser(m, attr map[string]any) {
	v, ok := m["user"]
	if !ok {
		return
	}

	src, ok := v.(map[string]any)
	if !ok {
		return
	}

	dst := make(map[string]any)

	m["user"] = dst
	v, ok = src["ids"]
	if !ok {
		return
	}

	ids, ok := v.(map[string]any)
	if !ok {
		return
	}

	v, ok = src["names"]
	if !ok {
		return
	}

	names, ok := v.(map[string]any)
	if !ok {
		return
	}

	transformUserID(ids, names, "a", "audit", dst)
	transformUserID(ids, names, "s", "saved", dst)
	transformUserID(ids, names, "fs", "filesystem", dst)

	if v, ok := src["selinux"]; ok {
		dst["selinux"] = v
	}
	m["user"] = dst

	// Insert user/group info into attributes map
	var uid, gid string

	if v, ok := ids["uid"]; ok {
		if s, ok := v.(string); ok {
			uid = s
		}
	}
	if v, ok := ids["gid"]; ok {
		if s, ok := v.(string); ok {
			gid = s
		}
	}

	if uid != "" {
		user := map[string]any{"id": uid}
		if v, ok := names["uid"]; ok {
			if s, ok := v.(string); ok && s != "" {
				user["name"] = s
			}
		}
		if gid != "" {
			group := map[string]any{"id": gid}
			if v, ok := names["gid"]; ok {
				if s, ok := v.(string); ok && s != "" {
					group["name"] = s
				}
			}
			user["group"] = group
		}
		attr["user"] = user
	}
}

func transformUserID(ids, names map[string]any, prefix, name string, dst map[string]any) {
	var uid, gid string

	if v, ok := ids[prefix+"uid"]; ok {
		if s, ok := v.(string); ok {
			uid = s
		}
	}
	if v, ok := ids[prefix+"gid"]; ok {
		if s, ok := v.(string); ok {
			gid = s
		}
	}

	if uid != "" {
		user := map[string]any{"id": uid}
		if v, ok := names[prefix+"uid"]; ok {
			if s, ok := v.(string); ok && s != "" {
				user["name"] = s
			}
		}
		if gid != "" {
			group := map[string]any{"id": gid}
			if v, ok := names[prefix+"gid"]; ok {
				if s, ok := v.(string); ok && s != "" {
					group["name"] = s
				}
			}
			user["group"] = group
		}
		dst[name] = user
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
