package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type RequestInfo struct {
	ID        string
	Method    string
	URL       string
	AgentID   string
	BodyBytes []byte
	Headers   http.Header
}

type Result struct {
	Decision      string
	Rule          string
	RequestID     string
	Redacted      bool
	RedactCount   int
	UpstreamCode  int
	UpstreamBody  []byte
	UpstreamError string
}

func NewRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func ExtractAgentID(r *http.Request, defaultHeader string) string {
	agent := r.Header.Get(defaultHeader)
	if agent != "" {
		return agent
	}
	if tok := r.Header.Get("Authorization"); strings.HasPrefix(tok, "Bearer ") {
		return tok[7:]
	}
	return "unknown"
}

func CopyBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}
	return io.ReadAll(r.Body)
}

func Forward(upstreamURL, method string, body []byte, headers http.Header) (int, []byte, error) {
	req, err := http.NewRequest(method, upstreamURL, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, fmt.Errorf("create request: %w", err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Del("X-Bastion-Agent")
	req.Header.Del("X-Bastion-Request-Id")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("forward: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}
