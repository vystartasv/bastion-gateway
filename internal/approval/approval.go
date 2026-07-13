package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Request struct {
	RequestID   string            `json:"request_id"`
	AgentID     string            `json:"agent_id"`
	Method      string            `json:"method"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	CreatedAt   string            `json:"created_at"`
	Status      string            `json:"status"` // pending, approved, denied
	UpstreamRes *UpstreamResult   `json:"upstream_result,omitempty"`
}

type UpstreamResult struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
	Error      string `json:"error,omitempty"`
}

type Store struct {
	dir string
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create approval dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Queue(req *Request) error {
	req.Status = "pending"
	req.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := filepath.Join(s.dir, req.RequestID+".json")
	return os.WriteFile(path, data, 0600)
}

func (s *Store) Approve(requestID, upstreamURL string) (*Request, error) {
	req, err := s.load(requestID)
	if err != nil {
		return nil, err
	}
	if req.Status != "pending" {
		return nil, fmt.Errorf("request %s is not pending (status: %s)", requestID, req.Status)
	}
	req.Status = "approved"
	s.save(req)
	return req, nil
}

func (s *Store) Deny(requestID string) error {
	req, err := s.load(requestID)
	if err != nil {
		return err
	}
	if req.Status != "pending" {
		return fmt.Errorf("request %s is not pending (status: %s)", requestID, req.Status)
	}
	req.Status = "denied"
	return s.save(req)
}

func (s *Store) List() []*Request {
	entries, _ := os.ReadDir(s.dir)
	var reqs []*Request
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		req, _ := s.load(strings.TrimSuffix(e.Name(), ".json"))
		if req != nil {
			reqs = append(reqs, req)
		}
	}
	return reqs
}

func (s *Store) load(requestID string) (*Request, error) {
	path := filepath.Join(s.dir, requestID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", requestID, err)
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parse %s: %w", requestID, err)
	}
	return &req, nil
}

func (s *Store) save(req *Request) error {
	data, _ := json.MarshalIndent(req, "", "  ")
	path := filepath.Join(s.dir, req.RequestID+".json")
	return os.WriteFile(path, data, 0600)
}
