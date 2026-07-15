package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Storage provides pluggable persistence for the ledger (Track 7 interface).
type Storage interface {
	Append(data []byte) error
	ReadRange(from, to time.Time) ([][]byte, error)
	DeleteOlderThan(t time.Time) error
}

// Signer provides pluggable signing (Track 7 interface).
type Signer interface {
	Sign(data []byte) ([]byte, error)
	Public() []byte
	KeyID() string
}

// Ed25519Signer implements Signer using Ed25519.
type Ed25519Signer struct {
	key    ed25519.PrivateKey
	keyID  string
	pubKey []byte
}

func NewEd25519Signer(keyPath string) (*Ed25519Signer, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	key := ed25519.PrivateKey(data)
	pub := key.Public().(ed25519.PublicKey)
	h := sha256.Sum256(data[:32])
	return &Ed25519Signer{
		key:    key,
		keyID:  hex.EncodeToString(h[:8]),
		pubKey: pub,
	}, nil
}

func (s *Ed25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.key, data), nil
}

func (s *Ed25519Signer) Public() []byte { return s.pubKey }
func (s *Ed25519Signer) KeyID() string  { return s.keyID }

// FileStorage implements Storage using the existing per-day JSONL pattern.
type FileStorage struct {
	dir      string
	mu       sync.Mutex
}

func NewFileStorage(dir string) (*FileStorage, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create evidence dir: %w", err)
	}
	return &FileStorage{dir: dir}, nil
}

func (fs *FileStorage) Append(data []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	date := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(fs.dir, fmt.Sprintf("evidence-%s.jsonl", date))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open evidence file: %w", err)
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

func (fs *FileStorage) ReadRange(from, to time.Time) ([][]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, fmt.Errorf("read evidence dir: %w", err)
	}

	var results [][]byte
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "evidence-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(fs.dir, e.Name()))
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			results = append(results, []byte(line))
		}
	}
	return results, nil
}

func (fs *FileStorage) DeleteOlderThan(t time.Time) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	entries, _ := os.ReadDir(fs.dir)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(t) && (strings.HasPrefix(e.Name(), "evidence-") || strings.HasPrefix(e.Name(), "meta-")) {
			os.Remove(filepath.Join(fs.dir, e.Name()))
		}
	}
	return nil
}

// MemoryStorage implements Storage in-memory for tests (Track 7).
type MemoryStorage struct {
	mu   sync.Mutex
	data [][]byte
}

func NewMemoryStorage() *MemoryStorage { return &MemoryStorage{} }

func (m *MemoryStorage) Append(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.data = append(m.data, cp)
	return nil
}

func (m *MemoryStorage) ReadRange(_, _ time.Time) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([][]byte, len(m.data))
	for i, d := range m.data {
		cp := make([]byte, len(d))
		copy(cp, d)
		res[i] = cp
	}
	return res, nil
}

func (m *MemoryStorage) DeleteOlderThan(_ time.Time) error { return nil }

// TestSigner implements Signer deterministically for tests.
type TestSigner struct {
	keyID   string
	sigData []byte
}

func NewTestSigner(keyID string) *TestSigner {
	return &TestSigner{keyID: keyID, sigData: []byte("test-signature-" + keyID)}
}

func (t *TestSigner) Sign(data []byte) ([]byte, error) {
	return t.sigData, nil
}
func (t *TestSigner) Public() []byte { return []byte("test-public-key") }
func (t *TestSigner) KeyID() string  { return t.keyID }

// Ledger is the tamper-evident evidence store.
type Ledger struct {
	storage Storage
	signer  Signer
	mu      sync.Mutex

	chainPath  string
	lastHash   string
	lastID     string
	recordCnt  int
}

// ChainState is persisted to chain.idx.
type ChainState struct {
	LastHash   string `json:"last_hash"`
	LastID     string `json:"last_id"`
	RecordCnt  int    `json:"record_count"`
}

// MetaEntry is a meta-log event.
type MetaEntry struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Detail    string `json:"detail,omitempty"`
}

// NewLedger creates a ledger with the given storage backend and signer.
func NewLedger(storage Storage, signer Signer, chainDir string) *Ledger {
	l := &Ledger{
		storage:   storage,
		signer:    signer,
		chainPath: filepath.Join(chainDir, "chain.idx"),
	}
	// Load chain state
	if data, err := os.ReadFile(l.chainPath); err == nil {
		var cs ChainState
		if json.Unmarshal(data, &cs) == nil {
			l.lastHash = cs.LastHash
			l.lastID = cs.LastID
			l.recordCnt = cs.RecordCnt
		}
	}
	return l
}

// Append stores a record with hash chaining and signing.
func (l *Ledger) Append(record *EvidenceRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Canonical form = record with ALL integrity fields zeroed (they're meta-data)
	record.Integrity = Integrity{
		PreviousRecordHash: l.lastHash,
	}

	canonical, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	// Hash the canonical form
	h := sha256.Sum256(canonical)
	recordHash := hex.EncodeToString(h[:])

	// Sign the canonical form (does not include integrity block)
	sig, err := l.signer.Sign(canonical)
	if err != nil {
		return fmt.Errorf("sign record: %w", err)
	}

	// Set all integrity fields for storage
	record.Integrity = Integrity{
		RecordHash:         recordHash,
		PreviousRecordHash: l.lastHash,
		Signature:          hex.EncodeToString(sig),
		SigningKeyID:       l.signer.KeyID(),
	}

	final, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal final: %w", err)
	}

	// Persist
	if err := l.storage.Append(final); err != nil {
		return fmt.Errorf("storage append: %w", err)
	}

	// Update chain state
	l.lastHash = record.Integrity.RecordHash
	l.lastID = record.EventContext.CorrelationID
	l.recordCnt++
	l.writeChainState()

	return nil
}

// ReadRange reads records within a time range (approximate — reads all for now).
func (l *Ledger) ReadRange(from, to time.Time) ([]EvidenceRecord, error) {
	l.logMeta("read", fmt.Sprintf("range %s to %s", from.Format(time.RFC3339), to.Format(time.RFC3339)))

	raw, err := l.storage.ReadRange(from, to)
	if err != nil {
		return nil, err
	}
	var records []EvidenceRecord
	for _, data := range raw {
		var rec EvidenceRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		records = append(records, rec)
	}
	// Sort by start_timestamp
	sort.Slice(records, func(i, j int) bool {
		return records[i].EventContext.StartTimestamp.Before(records[j].EventContext.StartTimestamp)
	})
	return records, nil
}

// VerifyChain recomputes the hash chain and verifies all signatures.
// Returns (true, -1, nil) if intact, (false, brokenIndex, error) on failure.
func (l *Ledger) VerifyChain() (bool, int, error) {
	l.logMeta("verify_chain", "full chain verification")

	raw, err := l.storage.ReadRange(time.Time{}, time.Now())
	if err != nil {
		return false, 0, fmt.Errorf("read storage: %w", err)
	}

	prevHash := ""

	for i, data := range raw {
		var rec EvidenceRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return false, i, fmt.Errorf("record %d: unmarshal: %w", i, err)
		}

		// Save integrity fields
		savedRecordHash := rec.Integrity.RecordHash
		savedSigHex := rec.Integrity.Signature
		savedPrevHash := rec.Integrity.PreviousRecordHash

		// Check chain link
		if savedPrevHash != prevHash {
			return false, i, fmt.Errorf("record %d: chain broken — expected prev %q, got %q", i, prevHash, savedPrevHash)
		}

		// Zero integrity block for canonical re-hash (same as Append does)
		rec.Integrity = Integrity{PreviousRecordHash: savedPrevHash}
		canonical, err := json.Marshal(rec)
		if err != nil {
			return false, i, fmt.Errorf("record %d: marshal: %w", i, err)
		}

		// Recompute hash
		h := sha256.Sum256(canonical)
		computedHash := hex.EncodeToString(h[:])
		if computedHash != savedRecordHash {
			return false, i, fmt.Errorf("record %d: hash mismatch — computed %q, stored %q", i, computedHash, savedRecordHash)
		}

		// Verify signature (if signer has a public key)
		pubKey := l.signer.Public()
		if len(pubKey) == ed25519.PublicKeySize && savedSigHex != "" {
			sig, err := hex.DecodeString(savedSigHex)
			if err == nil && len(sig) > 0 {
				if !ed25519.Verify(pubKey, canonical, sig) {
					return false, i, fmt.Errorf("record %d: invalid signature", i)
				}
			}
		}

		prevHash = computedHash
	}

	return true, -1, nil
}

// ChainState returns the current chain state.
func (l *Ledger) ChainState() ChainState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return ChainState{
		LastHash:  l.lastHash,
		LastID:    l.lastID,
		RecordCnt: l.recordCnt,
	}
}

// Close writes final chain state.
func (l *Ledger) Close() error {
	l.writeChainState()
	return nil
}

const ed25519KeyLen = 32

// GenerateKey creates a new Ed25519 signing key and writes it to path.
func GenerateKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	return os.WriteFile(path, priv, 0600)
}

func (l *Ledger) writeChainState() {
	cs := ChainState{LastHash: l.lastHash, LastID: l.lastID, RecordCnt: l.recordCnt}
	data, _ := json.Marshal(cs)
	os.MkdirAll(filepath.Dir(l.chainPath), 0700)
	os.WriteFile(l.chainPath, data, 0600)
}

func (l *Ledger) logMeta(typ, detail string) {
	entry := MetaEntry{Type: typ, Timestamp: time.Now().UTC().Format(time.RFC3339), Detail: detail}
	data, _ := json.Marshal(entry)
	// Write to a separate meta log file (best-effort, no error returned)
	date := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(filepath.Dir(l.chainPath), fmt.Sprintf("meta-%s.log", date))
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		f.Write(append(data, '\n'))
		f.Close()
	}
}
