package evidence

import (
	"testing"
	"time"
)

func TestLedgerAppendAndVerify(t *testing.T) {
	store := NewMemoryStorage()
	signer := NewTestSigner("test-key-1")
	ledger := NewLedger(store, signer, t.TempDir())

	rec := &EvidenceRecord{
		SchemaVersion: "1.0.0",
		Identity: Identity{
			Principal:  Principal{Name: "alice", Type: "human"},
			AuthMethod: "oidc",
			Role:       "operator",
		},
		EventContext: EventContext{
			StartTimestamp: time.Now().UTC(),
			EndTimestamp:   time.Now().UTC(),
			CorrelationID:  "corr-1",
			SessionID:      "sess-1",
			BastionVersion: "1.0.0",
			PolicyVersion:  "v1",
		},
		DecisionContent: DecisionContent{
			Action:      "allow",
			ToolOrModel: "GET api.example.com/data",
		},
		Reason: Reason{ReasonCode: "POLICY_ALLOW", Rationale: "allowed"},
	}

	if err := ledger.Append(rec); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Second record — builds on chain
	rec2 := &EvidenceRecord{
		SchemaVersion: "1.0.0",
		Identity:      Identity{Principal: Principal{Name: "bob", Type: "human"}, AuthMethod: "oidc", Role: "viewer"},
		EventContext: EventContext{
			StartTimestamp: time.Now().UTC(),
			EndTimestamp:   time.Now().UTC(),
			CorrelationID:  "corr-2",
			SessionID:      "sess-1",
			BastionVersion: "1.0.0",
			PolicyVersion:  "v1",
		},
		DecisionContent: DecisionContent{Action: "block", ToolOrModel: "DELETE /orders"},
		Reason:          Reason{ReasonCode: "POLICY_block", Rationale: "not allowed"},
	}
	if err := ledger.Append(rec2); err != nil {
		t.Fatalf("Append rec2: %v", err)
	}

	ok, idx, err := ledger.VerifyChain()
	if !ok {
		t.Fatalf("VerifyChain: broken at %d: %v", idx, err)
	}
}

func TestLedgerDetectsTamper(t *testing.T) {
	store := NewMemoryStorage()
	signer := NewTestSigner("test-key-1")
	ledger := NewLedger(store, signer, t.TempDir())

	// Append raw tampered data (bypassing ledger to simulate tamper)
	tamperedData := []byte(`{"schema_version":"1.0.0","identity":{"principal":{"name":"alice","type":"human"},"auth_method":"oidc","role":"operator"},"event_context":{"start_timestamp":"2026-07-15T00:00:00Z","end_timestamp":"2026-07-15T00:00:01Z","correlation_id":"corr-1","bastion_version":"1.0.0","policy_version":"v1"},"decision_content":{"action":"allow","tool_or_model":"GET /data"},"reason":{"reason_code":"POLICY_ALLOW","rationale":"allowed"},"integrity":{"record_hash":"tampered-hash","previous_record_hash":"","signature":"fake-sig","signing_key_id":"test-key-1"}}`)
	if err := store.Append(tamperedData); err != nil {
		t.Fatalf("store.Append tampered data: %v", err)
	}

	ok, idx, err := ledger.VerifyChain()
	if ok {
		t.Fatal("VerifyChain: expected tamper detection, got ok")
	}
	t.Logf("Tamper detected at record %d: %v", idx, err)
	if idx < 0 {
		t.Fatalf("expected broken record index >= 0, got %d", idx)
	}
}

func TestLedgerMetaLogging(t *testing.T) {
	store := NewMemoryStorage()
	signer := NewTestSigner("test-key-2")
	dir := t.TempDir()
	ledger := NewLedger(store, signer, dir)

	// ReadRange triggers meta-log
	_, err := ledger.ReadRange(time.Now().Add(-1*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}

	// VerifyChain triggers meta-log
	ledger.VerifyChain()
}
