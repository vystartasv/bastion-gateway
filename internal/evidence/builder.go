package evidence

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// RecordBuilder incrementally constructs an EvidenceRecord.
type RecordBuilder struct {
	record *EvidenceRecord
}

// NewRecordBuilder creates a builder pre-populated with schema_version and event_context.
func NewRecordBuilder(correlationID, sessionID, bastionVersion, policyVersion string) *RecordBuilder {
	return &RecordBuilder{
		record: &EvidenceRecord{
			SchemaVersion: "1.0.0",
			EventContext: EventContext{
				CorrelationID:  correlationID,
				SessionID:      sessionID,
				BastionVersion: bastionVersion,
				PolicyVersion:  policyVersion,
			},
		},
	}
}

// SetIdentity sets the identity block.
func (b *RecordBuilder) SetIdentity(res ResolveResult) *RecordBuilder {
	b.record.Identity = res.Identity
	return b
}

// SetDecision sets the decision content.
func (b *RecordBuilder) SetDecision(action, toolOrModel, modelVersion, matchedRule string) *RecordBuilder {
	b.record.DecisionContent = DecisionContent{
		Action:       action,
		ToolOrModel:  toolOrModel,
		ModelVersion: modelVersion,
	}
	if matchedRule != "" {
		b.record.Reason = Reason{
			ReasonCode: "POLICY_" + action,
			Rationale:  fmt.Sprintf("matched rule: %s", matchedRule),
		}
	} else {
		b.record.Reason = Reason{
			ReasonCode: "POLICY_" + action,
			Rationale:  "default policy decision",
		}
	}
	return b
}

// SetInput captures request metadata. Body is limited to 1KB (privacy by design).
func (b *RecordBuilder) SetInput(method, host, path string, headers http.Header, body []byte) *RecordBuilder {
	env := make(map[string]any)
	for k, vs := range headers {
		env[k] = vs
		if len(vs) == 1 {
			env[k] = vs[0]
		}
	}
	b.record.DecisionContent.InputEnvelope = env

	summary := ""
	if len(body) > 0 {
		summary = string(body)
		if len(summary) > 1024 {
			summary = summary[:1024]
		}
	}
	b.record.DecisionContent.InputSummary = summary

	// Build the tool string from method+host+path
	b.record.DecisionContent.ToolOrModel = method + " " + host + path

	return b
}

// SetOutput captures response metadata. Body is limited to 1KB.
func (b *RecordBuilder) SetOutput(statusCode int, body []byte, err error) *RecordBuilder {
	env := make(map[string]any)
	env["status_code"] = statusCode
	b.record.DecisionContent.OutputEnvelope = env

	summary := ""
	if len(body) > 0 {
		summary = string(body)
		if len(summary) > 1024 {
			summary = summary[:1024]
		}
	}
	b.record.DecisionContent.OutputSummary = summary

	if err != nil {
		b.record.DecisionContent.OutputSummary = fmt.Sprintf("error: %v", err)
	}

	return b
}

// SetTimestamps sets start and end timestamps.
func (b *RecordBuilder) SetTimestamps(start, end time.Time) *RecordBuilder {
	b.record.EventContext.StartTimestamp = start
	b.record.EventContext.EndTimestamp = end
	return b
}

// SetReasonCode overrides the default reason.
func (b *RecordBuilder) SetReasonCode(reasonCode, rationale string) *RecordBuilder {
	b.record.Reason = Reason{
		ReasonCode: reasonCode,
		Rationale:  rationale,
	}
	return b
}

// SetReferences sets the references block.
func (b *RecordBuilder) SetReferences(provenanceIDs, datasetIDs, promptIDs []string) *RecordBuilder {
	b.record.References = References{
		ProvenanceIDs: provenanceIDs,
		DatasetIDs:    datasetIDs,
		PromptIDs:     promptIDs,
	}
	return b
}

// Build returns the constructed record and resets the builder.
func (b *RecordBuilder) Build() *EvidenceRecord {
	r := b.record
	b.record = nil
	return r
}

// RecordToJSON marshals the record to indented JSON for stdout logging.
func RecordToJSON(r *EvidenceRecord) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data)
}
