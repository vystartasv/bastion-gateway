package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateValidRecord(t *testing.T) {
	if err := Validate(loadRecord(t, "valid-record.json")); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingPrincipal(t *testing.T) {
	if err := Validate(loadRecord(t, "invalid-missing-identity.json")); err == nil {
		t.Fatal("Validate() error = nil, want missing identity.principal rejection")
	}
}

func TestValidateRejectsBotStyleHuman(t *testing.T) {
	if err := Validate(loadRecord(t, "invalid-bot-human.json")); err == nil {
		t.Fatal("Validate() error = nil, want bot-style human rejection")
	}
}

func loadRecord(t *testing.T, name string) EvidenceRecord {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "evidence", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var record EvidenceRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	return record
}
