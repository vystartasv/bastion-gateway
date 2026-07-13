package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Record struct {
	RequestID     string `json:"request_id"`
	Timestamp     string `json:"timestamp"`
	AgentID       string `json:"agent_id"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	Decision      string `json:"decision"`
	MatchedRule   string `json:"matched_rule,omitempty"`
	RedactCount   int    `json:"redact_count"`
	UpstreamCode  int    `json:"upstream_code,omitempty"`
	UpstreamError string `json:"upstream_error,omitempty"`
	Signature     string `json:"signature,omitempty"`
	SigningKeyID  string `json:"signing_key_id,omitempty"`
}

type Store struct {
	mu       sync.Mutex
	dir      string
	signKey  ed25519.PrivateKey
	keyID    string
	signed   bool
}

func NewStore(dir string, keyPath string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	s := &Store{dir: dir}
	if keyPath != "" {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot read signing key %s: %v (audit will be unsigned)\n", keyPath, err)
		} else {
			key := ed25519.PrivateKey(keyData)
			s.signKey = key
			h := sha256.Sum256(keyData)
			s.keyID = hex.EncodeToString(h[:8])
			s.signed = true
		}
	}
	if !s.signed {
		fmt.Fprintf(os.Stderr, "WARNING: no signing key mounted — audit log is UNSIGNED\n")
	}
	return s, nil
}

func (s *Store) Append(r Record) error {
	r.Timestamp = time.Now().UTC().Format(time.RFC3339)
	r.SigningKeyID = s.keyID

	data, _ := json.Marshal(r)
	if s.signed {
		sig := ed25519.Sign(s.signKey, data)
		r.Signature = hex.EncodeToString(sig)
		data, _ = json.Marshal(r)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Append to daily file
	date := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(s.dir, fmt.Sprintf("audit-%s.jsonl", date))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}

func (s *Store) Export() ([]Record, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read audit dir: %w", err)
	}
	var records []Record
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "audit-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var rec Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			records = append(records, rec)
		}
	}
	return records, nil
}

func GenerateKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	return os.WriteFile(path, priv, 0600)
}
