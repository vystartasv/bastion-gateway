package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`default: deny
agents:
  test:
    allow:
      - GET api.example.com/*
`), 0644)

	p, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Default != "deny" {
		t.Fatalf("expected deny, got %s", p.Default)
	}
}

func TestLoadRejectsNonDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`default: allow
agents: {}
`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-deny default")
	}
}

func TestEvaluateAgentNotFound(t *testing.T) {
	p := &Policy{Default: "deny", Agents: map[string]*Agent{}}
	r := p.Evaluate("unknown", "GET", "api.example.com", "/test")
	if r.Decision != Deny {
		t.Fatalf("expected DENY, got %s", r.Decision)
	}
}

func TestEvaluateAllow(t *testing.T) {
	p := &Policy{Default: "deny", Agents: map[string]*Agent{
		"test": {Allow: []string{"GET api.example.com/*"}},
	}}
	r := p.Evaluate("test", "GET", "api.example.com", "/test")
	if r.Decision != Allow {
		t.Fatalf("expected ALLOW, got %s", r.Decision)
	}
}

func TestEvaluateDeny(t *testing.T) {
	p := &Policy{Default: "deny", Agents: map[string]*Agent{
		"test": {},
	}}
	r := p.Evaluate("test", "DELETE", "api.example.com", "/data")
	if r.Decision != Deny {
		t.Fatalf("expected DENY, got %s", r.Decision)
	}
}

func TestEvaluateHold(t *testing.T) {
	p := &Policy{Default: "deny", Agents: map[string]*Agent{
		"test": {Hold: []string{"DELETE *"}},
	}}
	r := p.Evaluate("test", "DELETE", "api.example.com", "/data")
	if r.Decision != Hold {
		t.Fatalf("expected HOLD, got %s", r.Decision)
	}
}
