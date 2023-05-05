// Copyright 2020, OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package skywalkingexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/skywalkingexporter"

import (
	"net/url"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	v3 "skywalking.apache.org/repo/goapi/collect/common/v3"
	tracepb "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func spanKindToSwSpanType(kind ptrace.SpanKind) (t tracepb.SpanType) {
	switch kind {
	case ptrace.SpanKindConsumer:
		fallthrough
	case ptrace.SpanKindServer:
		t = tracepb.SpanType_Entry
	case ptrace.SpanKindProducer:
		fallthrough
	case ptrace.SpanKindClient:
		t = tracepb.SpanType_Exit
	case ptrace.SpanKindInternal:
		fallthrough
	case ptrace.SpanKindUnspecified:
		t = tracepb.SpanType_Local
	}
	return
}

func traceSpanToSwTraceSpan(span ptrace.Span, serviceName string, serviceInstance string) (swSpan *tracepb.SpanObject) {
	attrs := span.Attributes()
	swTags := make([]*v3.KeyStringValuePair, 0, 20)
	attrs.Range(func(k string, v pcommon.Value) bool {
		if k != "" && v.Type() != pcommon.ValueTypeEmpty {
			pair := &v3.KeyStringValuePair{
				// Key: "otel." + k,
				Key:   k,
				Value: v.AsString(),
			}
			swTags = append(swTags, pair)
		}
		return true
	})

	events := span.Events()
	swLogs := make([]*tracepb.Log, 0, 20)
	for i := 0; i < events.Len(); i++ {
		event := events.At(i)
		eventName := event.Name()
		eventAttrs := event.Attributes()
		data := make([]*v3.KeyStringValuePair, 0, 10)

		data = append(data, &v3.KeyStringValuePair{
			Key:   "name",
			Value: eventName,
		})
		eventAttrs.Range(func(k string, v pcommon.Value) bool {
			if k != "" && v.Type() != pcommon.ValueTypeEmpty {
				data = append(data, &v3.KeyStringValuePair{
					Key:   k,
					Value: v.AsString(),
				})
			}
			return true
		})

		swLogs = append(swLogs, &tracepb.Log{
			Time: event.Timestamp().AsTime().UnixMilli(),
			Data: data,
		})
	}

	swRefs := make([]*tracepb.SegmentReference, 0, 10)
	attrParentEndPoint, _ := attrs.Get("http.url")
	// attrNetworkAddressUsedAtPeer, _ = attrs.Get("net.peer.ip")
	swRefs = append(swRefs, &tracepb.SegmentReference{
		// since scopeSpans are produced by one client
		RefType:               tracepb.RefType_CrossThread,
		TraceId:               span.TraceID().String(),
		ParentTraceSegmentId:  span.ParentSpanID().String(),
		ParentSpanId:          0,
		ParentService:         serviceName,
		ParentServiceInstance: serviceInstance,
		ParentEndpoint:        attrParentEndPoint.AsString(),
		// NetworkAddressUsedAtPeer: ,
	})

	name := span.Name()
	method, _ := attrs.Get("http.method")
	rawURL := attrParentEndPoint.AsString()
	if method.AsString() != "" && rawURL != "" {
		parsedURL, parsedErr := url.Parse(rawURL)
		if parsedErr == nil {
			name = method.AsString() + parsedURL.Path
		}
	}
	swSpan = &tracepb.SpanObject{
		SpanId:        0,
		ParentSpanId:  -1,
		StartTime:     span.StartTimestamp().AsTime().UnixMilli(),
		EndTime:       span.EndTimestamp().AsTime().UnixMilli(),
		Refs:          swRefs,
		OperationName: name,
		SpanType:      spanKindToSwSpanType(span.Kind()),
		SpanLayer:     tracepb.SpanLayer_Unknown,
		// ComponentId
		IsError: span.Status().Code() == ptrace.StatusCodeError,
		Tags:    swTags,
		Logs:    swLogs,
	}
	return
}

func tracesRecordToSegmentObjectSlice(
	md ptrace.Traces,
) (segments []*tracepb.SegmentObject) {
	resSpans := md.ResourceSpans()

	for i := 0; i < resSpans.Len(); i++ {
		resSpan := resSpans.At(i)
		resAttrs := resSpan.Resource().Attributes()
		serviceName, _ := resAttrs.Get("service.name")
		serviceInstance, _ := resAttrs.Get("service.instance.id")
		serviceVersion, _ := resAttrs.Get("service.version")

		// fmt.Println("Resource attributes", resSpan.Resource().Attributes())
		resSpanSlices := resSpan.ScopeSpans()

		for j := 0; j < resSpanSlices.Len(); j++ {
			slice := resSpanSlices.At(j)
			scopeSpans := slice.Spans()

			for k := 0; k < scopeSpans.Len(); k++ {
				span := scopeSpans.At(k)
				swSpan := traceSpanToSwTraceSpan(span, serviceName.Str(), serviceInstance.Str())
				segment := &tracepb.SegmentObject{
					TraceId:        span.TraceID().String(),
					TraceSegmentId: span.SpanID().String(),
					Spans: []*tracepb.SpanObject{
						swSpan,
					},
					Service:         serviceName.Str(),
					ServiceInstance: firstNonEmpty(serviceInstance.Str(), serviceVersion.Str()),
				}
				segments = append(segments, segment)
			}
		}
	}
	return segments
}
