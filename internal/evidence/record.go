// Package evidence defines the auditable decision record emitted by Bastion.
package evidence

import "time"

// EvidenceRecord is a version 1.0.0 Bastion Evidence Record.
type EvidenceRecord struct {
	SchemaVersion   string          `json:"schema_version"`
	Identity        Identity        `json:"identity"`
	EventContext    EventContext    `json:"event_context"`
	DecisionContent DecisionContent `json:"decision_content"`
	Reason          Reason          `json:"reason"`
	References      References      `json:"references"`
	Integrity       Integrity       `json:"integrity"`
}

type Identity struct {
	Principal  Principal `json:"principal"`
	AuthMethod string    `json:"auth_method"`
	Role       string    `json:"role"`
}

type Principal struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type EventContext struct {
	StartTimestamp time.Time `json:"start_timestamp"`
	EndTimestamp   time.Time `json:"end_timestamp"`
	CorrelationID  string    `json:"correlation_id"`
	SessionID      string    `json:"session_id,omitempty"`
	BastionVersion string    `json:"bastion_version"`
	PolicyVersion  string    `json:"policy_version"`
}

type DecisionContent struct {
	Action         string         `json:"action"`
	ToolOrModel    string         `json:"tool_or_model"`
	ModelVersion   string         `json:"model_version"`
	InputSummary   string         `json:"input_summary"`
	OutputSummary  string         `json:"output_summary"`
	InputEnvelope  map[string]any `json:"input_envelope,omitempty"`
	OutputEnvelope map[string]any `json:"output_envelope,omitempty"`
}

type Reason struct {
	ReasonCode string `json:"reason_code"`
	Rationale  string `json:"rationale"`
}

type References struct {
	ProvenanceIDs []string `json:"provenance_ids,omitempty"`
	DatasetIDs    []string `json:"dataset_ids,omitempty"`
	PromptIDs     []string `json:"prompt_ids,omitempty"`
}

type Integrity struct {
	RecordHash         string `json:"record_hash"`
	PreviousRecordHash string `json:"previous_record_hash"`
	Signature          string `json:"signature,omitempty"`
	SigningKeyID       string `json:"signing_key_id"`
}
