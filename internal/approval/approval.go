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

// OversightRecord tracks a human override/approval (Track 4, Art 14).
type OversightRecord struct {
	RequestID      string `json:"request_id"`
	CorrelationID  string `json:"correlation_id"`
	ApproverName   string `json:"approver_name"`
	ApproverRole   string `json:"approver_role"`
	Decision       string `json:"decision"` // approved / denied / overridden
	Reason         string `json:"reason"`
	Timestamp      string `json:"timestamp"`
	LinkedRecordID string `json:"linked_record_id"`
}

type Store struct {
	dir           string
	oversightFile string
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create approval dir: %w", err)
	}
	return &Store{
		dir:           dir,
		oversightFile: filepath.Join(dir, "oversight.log"),
	}, nil
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
	return s.resolve(requestID, "approved", "", "")
}

// ApproveWithOversight approves with full Art 14 tracking.
func (s *Store) ApproveWithOversight(requestID, approverName, approverRole, reason string) (*Request, error) {
	if reason == "" {
		return nil, fmt.Errorf("reason is required for oversight")
	}
	return s.resolve(requestID, "approved", approverName, reason)
}

func (s *Store) Deny(requestID string) error {
	_, err := s.resolve(requestID, "denied", "", "")
	return err
}

// DenyWithOversight denies with full Art 14 tracking.
func (s *Store) DenyWithOversight(requestID, approverName, approverRole, reason string) error {
	if reason == "" {
		return fmt.Errorf("reason is required for oversight")
	}
	_, err := s.resolve(requestID, "denied", approverName, reason)
	return err
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

// resolve updates the request status and writes an oversight record if approverName is set.
func (s *Store) resolve(requestID, newStatus, approverName, reason string) (*Request, error) {
	req, err := s.load(requestID)
	if err != nil {
		return nil, err
	}
	if req.Status != "pending" {
		return nil, fmt.Errorf("request %s is not pending (status: %s)", requestID, req.Status)
	}
	req.Status = newStatus
	if err := s.save(req); err != nil {
		return nil, err
	}

	// Write oversight record if approver is named
	if approverName != "" {
		o := OversightRecord{
			RequestID:    requestID,
			Decision:     newStatus,
			ApproverName: approverName,
			ApproverRole: approverName, // ponytail: role = name for v1, revisit if RBAC needed
			Reason:       reason,
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(o)
		f, err := os.OpenFile(s.oversightFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			f.Write(append(data, '\n'))
			f.Close()
		}
	}

	return req, nil
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
