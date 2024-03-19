// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elasticsearchexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"

import (
	"bytes"
	"encoding/json"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter/internal/objmodel"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/traceutil"
)

type mappingModel interface {
	encodeLog(pcommon.Resource, plog.LogRecord, pcommon.InstrumentationScope /*resourceSchemaUrl*/, string /*scopeSchemaUrl*/, string) ([]byte, error)
	encodeSpan(pcommon.Resource, ptrace.Span, pcommon.InstrumentationScope) ([]byte, error)
}

// encodeModel tries to keep the event as close to the original open telemetry semantics as is.
// No fields will be mapped by default.
//
// Field deduplication and dedotting of attributes is supported by the encodeModel.
//
// See: https://github.com/open-telemetry/oteps/blob/master/text/logs/0097-log-data-model.md
type encodeModel struct {
	dedup bool
	dedot bool
	mode  MappingMode
}

const (
	traceIDField   = "traceID"
	spanIDField    = "spanID"
	attributeField = "attribute"
)

// Mapping for Otel is borrowed from https://github.com/elastic/opentelemetry-dev/blob/main/docs/ingest/docmarshaler/logs.go
// setLogBody sets either doc.BodyText or doc.BodyStructured.
//
// If body is a map, or contains a map nested within an array,
// then we set BodyStructured. Otherwise we set BodyText,
// coercing any non-string types to strings.
func setLogBody(doc *objmodel.Document, body pcommon.Value) {
	switch body.Type() {
	case pcommon.ValueTypeMap:
		doc.AddAttribute("body_structured", body)
	case pcommon.ValueTypeSlice:
		slice := body.Slice()
		for i := 0; i < slice.Len(); i++ {
			switch slice.At(i).Type() {
			case pcommon.ValueTypeMap, pcommon.ValueTypeSlice:
				doc.AddAttribute("body_structured", body)
				return
			}
		}

		// TODO: likely can be optimized
		bodyTextVal := pcommon.NewValueSlice()
		bodyText := bodyTextVal.Slice()
		bodyText.EnsureCapacity(slice.Len())

		for i := 0; i < slice.Len(); i++ {
			elem := slice.At(i)
			bodyText.AppendEmpty().SetStr(elem.AsString())
		}
		doc.AddAttribute("body_text", bodyTextVal)
	default:
		doc.AddString("body_text", body.AsString())
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// TODO: Current implementation needs to be refactored, the resourceLogs.SchemUrl and scopeLogs.SchemaUrl are not passed in
// so hacked it in for now.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// The more efficient logs parsing seems to be already implemented in
// https://github.com/elastic/opentelemetry-dev/blob/main/docs/ingest/docmarshaler/logs.go
// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
func (m *encodeModel) encodeLog(resource pcommon.Resource, record plog.LogRecord, scope pcommon.InstrumentationScope, resourceSchemaUrl, scopeSchemaUrl string) ([]byte, error) {
	var document objmodel.Document

	switch m.mode {
	case MappingECS:
		document.AddTimestamp("@timestamp", record.Timestamp()) // We use @timestamp in order to ensure that we can index if the default data stream logs template is used.
		document.AddTraceID("trace.id", record.TraceID())
		document.AddSpanID("span.id", record.SpanID())

		if f := record.Flags(); f != 0 {
			document.AddInt("trace.flags", int64(record.Flags()))
		}

		if n := record.SeverityNumber(); n != plog.SeverityNumberUnspecified {
			document.AddInt("log.syslog.severity.code", int64(record.SeverityNumber()))
			document.AddString("log.syslog.severity.name", record.SeverityText())
		}

		document.AddAttribute("message", record.Body())

		fieldMapper := func(k string) string {
			switch k {
			case "exception.type":
				return "error.type"
			case "exception.message":
				return "error.message"
			case "exception.stacktrace":
				return "error.stack_trace"
			default:
				return k
			}
		}

		resource.Attributes().Range(func(k string, v pcommon.Value) bool {
			k = fieldMapper(k)
			document.AddAttribute(k, v)
			return true
		})
		scope.Attributes().Range(func(k string, v pcommon.Value) bool {
			k = fieldMapper(k)
			document.AddAttribute(k, v)
			return true
		})
		record.Attributes().Range(func(k string, v pcommon.Value) bool {
			k = fieldMapper(k)
			document.AddAttribute(k, v)
			return true
		})
	case MappingOTel:
		document.AddTimestamp("@timestamp", record.Timestamp())
		document.AddTimestamp("observed_timestamp", record.ObservedTimestamp())

		// Could be enriched with configurable datastream options
		// DataStream: marshalgen.DataStream{
		// 	Type:      "logs",
		// 	Dataset:   "generic",
		// 	Namespace: "default",
		// },

		document.AddString("span_id", record.SpanID().String())
		document.AddString("trace_id", record.TraceID().String())
		document.AddInt("trace_flags", int64(byte(record.Flags())))
		document.AddString("severity_text", record.SeverityText())
		document.AddInt("severity_number", int64(record.SeverityNumber()))

		document.AddString("schema_url", scopeSchemaUrl)

		res := pcommon.NewValueMap()
		mres := res.Map()
		resourceAttributes := mres.PutEmptyMap("attributes")

		mres.PutInt("dropped_attributes_count", int64(record.DroppedAttributesCount()))
		mres.PutStr("schema_url", resourceSchemaUrl)
		resource.Attributes().CopyTo(resourceAttributes)

		document.AddAttribute("resource", res)

		sco := pcommon.NewValueMap()
		msco := sco.Map()
		scopeAttributes := mres.PutEmptyMap("attributes")

		msco.PutStr("name", scope.Name())
		msco.PutStr("version", scope.Version())
		msco.PutInt("dropped_attributes_count", int64(scope.DroppedAttributesCount()))
		scope.Attributes().CopyTo(scopeAttributes)

		document.AddAttribute("scope", sco)

		document.AddAttributes("attributes", record.Attributes())
		document.AddInt("dropped_attributes_count", int64(record.DroppedAttributesCount()))

		setLogBody(&document, record.Body())

	default:
		document.AddTimestamp("@timestamp", record.Timestamp()) // We use @timestamp in order to ensure that we can index if the default data stream logs template is used.
		document.AddTraceID("TraceId", record.TraceID())
		document.AddSpanID("SpanId", record.SpanID())
		document.AddInt("TraceFlags", int64(record.Flags()))
		document.AddString("SeverityText", record.SeverityText())
		document.AddInt("SeverityNumber", int64(record.SeverityNumber()))
		document.AddAttribute("Body", record.Body())
		m.encodeAttributes(&document, record.Attributes())
		document.AddAttributes("Attributes", record.Attributes())
		document.AddAttributes("Resource", resource.Attributes())
		document.AddAttributes("Scope", scopeToAttributes(scope))
	}

	if m.dedup {
		document.Dedup()
	} else if m.dedot {
		document.Sort()
	}

	var buf bytes.Buffer
	err := document.Serialize(&buf, m.dedot, m.mode == MappingOTel)
	return buf.Bytes(), err
}

func (m *encodeModel) encodeSpan(resource pcommon.Resource, span ptrace.Span, scope pcommon.InstrumentationScope) ([]byte, error) {
	var document objmodel.Document
	document.AddTimestamp("@timestamp", span.StartTimestamp()) // We use @timestamp in order to ensure that we can index if the default data stream logs template is used.
	document.AddTimestamp("EndTimestamp", span.EndTimestamp())
	document.AddTraceID("TraceId", span.TraceID())
	document.AddSpanID("SpanId", span.SpanID())
	document.AddSpanID("ParentSpanId", span.ParentSpanID())
	document.AddString("Name", span.Name())
	document.AddString("Kind", traceutil.SpanKindStr(span.Kind()))
	document.AddInt("TraceStatus", int64(span.Status().Code()))
	document.AddString("TraceStatusDescription", span.Status().Message())
	document.AddString("Link", spanLinksToString(span.Links()))
	m.encodeAttributes(&document, span.Attributes())
	document.AddAttributes("Resource", resource.Attributes())
	m.encodeEvents(&document, span.Events())
	document.AddInt("Duration", durationAsMicroseconds(span.StartTimestamp().AsTime(), span.EndTimestamp().AsTime())) // unit is microseconds
	document.AddAttributes("Scope", scopeToAttributes(scope))

	if m.dedup {
		document.Dedup()
	} else if m.dedot {
		document.Sort()
	}

	var buf bytes.Buffer
	err := document.Serialize(&buf, m.dedot, m.mode == MappingOTel)
	return buf.Bytes(), err
}

func (m *encodeModel) encodeAttributes(document *objmodel.Document, attributes pcommon.Map) {
	key := "Attributes"
	if m.mode == MappingRaw {
		key = ""
	}
	document.AddAttributes(key, attributes)
}

func (m *encodeModel) encodeEvents(document *objmodel.Document, events ptrace.SpanEventSlice) {
	key := "Events"
	if m.mode == MappingRaw {
		key = ""
	}
	document.AddEvents(key, events)
}

func spanLinksToString(spanLinkSlice ptrace.SpanLinkSlice) string {
	linkArray := make([]map[string]any, 0, spanLinkSlice.Len())
	for i := 0; i < spanLinkSlice.Len(); i++ {
		spanLink := spanLinkSlice.At(i)
		link := map[string]any{}
		link[spanIDField] = traceutil.SpanIDToHexOrEmptyString(spanLink.SpanID())
		link[traceIDField] = traceutil.TraceIDToHexOrEmptyString(spanLink.TraceID())
		link[attributeField] = spanLink.Attributes().AsRaw()
		linkArray = append(linkArray, link)
	}
	linkArrayBytes, _ := json.Marshal(&linkArray)
	return string(linkArrayBytes)
}

// durationAsMicroseconds calculate span duration through end - start nanoseconds and converts time.Time to microseconds,
// which is the format the Duration field is stored in the Span.
func durationAsMicroseconds(start, end time.Time) int64 {
	return (end.UnixNano() - start.UnixNano()) / 1000
}

func scopeToAttributes(scope pcommon.InstrumentationScope) pcommon.Map {
	attrs := pcommon.NewMap()
	attrs.PutStr("name", scope.Name())
	attrs.PutStr("version", scope.Version())
	for k, v := range scope.Attributes().AsRaw() {
		attrs.PutStr(k, v.(string))
	}
	return attrs
}
