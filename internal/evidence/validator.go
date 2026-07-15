package evidence

import (
	"fmt"
	"strings"
)

// Validate verifies that record satisfies the version 1.0.0 schema and
// Bastion's human-principal restrictions.
func Validate(record EvidenceRecord) error {
	if record.SchemaVersion != "1.0.0" {
		return fmt.Errorf("schema_version must be 1.0.0")
	}
	if record.Identity.Principal.Name == "" || record.Identity.Principal.Type == "" {
		return fmt.Errorf("identity.principal is required")
	}
	if record.Identity.Principal.Type != "human" && record.Identity.Principal.Type != "delegated" {
		return fmt.Errorf("identity.principal.type must be human or delegated")
	}
	if record.Identity.Principal.Type == "human" {
		if strings.HasPrefix(record.Identity.Principal.Name, "svc-") || strings.HasPrefix(record.Identity.Principal.Name, "bot-") {
			return fmt.Errorf("human principal cannot use a service-account name")
		}
	}
	if record.EventContext.StartTimestamp.IsZero() || record.EventContext.EndTimestamp.IsZero() {
		return fmt.Errorf("event_context timestamps are required")
	}
	if record.DecisionContent.Action != "allow" && record.DecisionContent.Action != "block" && record.DecisionContent.Action != "queue" && record.DecisionContent.Action != "redact" {
		return fmt.Errorf("decision_content.action is invalid")
	}
	return nil
}
