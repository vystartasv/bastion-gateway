package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vystartasv/bastion-gateway/internal/approval"
	"github.com/vystartasv/bastion-gateway/internal/evidence"
	"github.com/vystartasv/bastion-gateway/internal/policy"
	"github.com/vystartasv/bastion-gateway/internal/proxy"
	"github.com/vystartasv/bastion-gateway/internal/redact"
)

var (
	pol              *policy.Policy
	approvalStore    *approval.Store
	redactEngine     *redact.Engine
	agentHeader      = "X-Bastion-Agent"
	sessionID        string
	bastionVersion   = "1.0.0"
	identityResolver *evidence.IdentityResolver
	evidenceLedger   *evidence.Ledger
)

func main() {
	port := getEnv("PORT", "8080")
	policyPath := getEnv("POLICY", "/policy.yaml")
	evidenceDir := getEnv("EVIDENCE_DIR", "/var/bastion/evidence")
	approvalDir := getEnv("APPROVAL_DIR", "/var/bastion/approvals")
	signKeyPath := getEnv("SIGN_KEY", "/var/bastion/signing.key")
	identitiesPath := getEnv("IDENTITIES", "")
	requirePrincipal := getEnv("REQUIRE_PRINCIPAL", "false") == "true"
	retentionDays := getEnvInt("EVIDENCE_RETENTION_DAYS", 183)

	// Retention floor check (Art 26(6))
	if retentionDays < 183 {
		log.Fatalf("EVIDENCE_RETENTION_DAYS (%d) below minimum 183 (6 months per Art 26(6))", retentionDays)
	}

	// Session identity
	hostname, _ := os.Hostname()
	sessionID = fmt.Sprintf("%s-%d", hostname, os.Getpid())

	var err error
	pol, err = policy.Load(policyPath)
	if err != nil {
		log.Fatalf("FAILED: policy load: %v", err)
	}
	log.Printf("Policy loaded: %s", policyPath)

	approvalStore, err = approval.NewStore(approvalDir)
	if err != nil {
		log.Fatalf("FAILED: approval store: %v", err)
	}

	// Build redaction engine
	var redactRules []redact.Rule
	for _, r := range pol.Redact {
		switch r.Type {
		case "builtin":
			redactRules = append(redactRules, redact.BuiltinRules([]string{r.Name})...)
		case "regex":
			re, err := redact.NewRegexp(r.Pattern)
			if err != nil {
				log.Fatalf("invalid redact regex %q: %v", r.Pattern, err)
			}
			redactRules = append(redactRules, redact.Rule{Type: "regex", Name: "user-regex", Pattern: re})
		}
	}
	redactEngine = redact.ParseRedactRules(redactRules)
	log.Printf("Redaction: %d rules loaded", len(redactRules))

	// Build identity resolver
	identityResolver = evidence.NewIdentityResolver(identitiesPath, requirePrincipal)

	// Setup evidence ledger (Track 3)
	var signer evidence.Signer
	if _, err := os.Stat(signKeyPath); os.IsNotExist(err) {
		log.Printf("Generating new signing key: %s", signKeyPath)
		if err := evidence.GenerateKey(signKeyPath); err != nil {
			log.Fatalf("generate key: %v", err)
		}
	}
	signer, err = evidence.NewEd25519Signer(signKeyPath)
	if err != nil {
		log.Fatalf("FAILED: signer: %v", err)
	}

	storage, err := evidence.NewFileStorage(evidenceDir)
	if err != nil {
		log.Fatalf("FAILED: evidence storage: %v", err)
	}
	evidenceLedger = evidence.NewLedger(storage, signer, evidenceDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRequest)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("Shutting down...")
		evidenceLedger.Close()
		server.Close()
	}()

	log.Printf("Bastion Gateway listening on :%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now().UTC()

	reqID := proxy.NewRequestID()
	agentID := proxy.ExtractAgentID(r, agentHeader)
	body, _ := proxy.CopyBody(r)

	// Evidence: correlation ID
	correlationID := evidence.EnsureCorrelationID(r)

	// Redact
	redactedBody, redactMatch := redactEngine.Apply(body)

	// Evidence: build record
	policyVersion := getEnv("POLICY_VERSION", "2026-07-13")
	builder := evidence.NewRecordBuilder(correlationID, sessionID, bastionVersion, policyVersion)

	// Resolve identity
	bearerToken := ""
	if tok := r.Header.Get("Authorization"); strings.HasPrefix(tok, "Bearer ") {
		bearerToken = tok[7:]
	}
	ident := identityResolver.Resolve(agentID, bearerToken)
	if ident.Err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"bastion": "denied",
			"reason":  "unattributed",
		})
		builder.SetIdentity(ident).
			SetDecision("block", r.Method+" "+r.Host+r.URL.Path, "", "").
			SetInput(r.Method, r.Host, r.URL.Path, r.Header, redactedBody).
			SetOutput(403, nil, ident.Err).
			SetTimestamps(startTime, time.Now().UTC())
		record := builder.Build()
		persistRecord(record, redactMatch.Count)
		return
	}
	builder.SetIdentity(ident)

	// Evaluate policy
	result := pol.Evaluate(agentID, r.Method, r.Host, r.URL.Path)

	// Build evidence input (after redaction)
	builder.SetInput(r.Method, r.Host, r.URL.Path, r.Header, redactedBody)

	switch string(result.Decision) {
	case string(policy.Allow):
		code, upstreamBody, err := proxy.Forward("https://"+r.Host+r.URL.Path, r.Method, redactedBody, r.Header)
		if err != nil {
			http.Error(w, `{"bastion":"upstream_error"}`, 502)
			builder.SetDecision("allow", r.Method+" "+r.Host+r.URL.Path, "", result.Rule).
				SetOutput(code, upstreamBody, err).
				SetTimestamps(startTime, time.Now().UTC())
		} else {
			w.WriteHeader(code)
			w.Write(upstreamBody)
			builder.SetDecision("allow", r.Method+" "+r.Host+r.URL.Path, "", result.Rule).
				SetOutput(code, upstreamBody, nil).
				SetTimestamps(startTime, time.Now().UTC())
		}
	case string(policy.Hold):
		req := &approval.Request{
			RequestID: reqID,
			AgentID:   agentID,
			Method:    r.Method,
			Host:      r.Host,
			Path:      r.URL.Path,
			Body:      string(redactedBody),
			Headers:   flattenHeaders(r.Header),
		}
		approvalStore.Queue(req)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"bastion":    "held",
			"request_id": reqID,
		})
		builder.SetDecision("queue", r.Method+" "+r.Host+r.URL.Path, "", result.Rule).
			SetOutput(http.StatusAccepted, nil, nil).
			SetTimestamps(startTime, time.Now().UTC())
	default: // DENY
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"bastion":    "denied",
			"request_id": reqID,
		})
		builder.SetDecision("block", r.Method+" "+r.Host+r.URL.Path, "", result.Rule).
			SetOutput(http.StatusForbidden, nil, nil).
			SetTimestamps(startTime, time.Now().UTC())
	}

	// Persist evidence record to ledger
	record := builder.Build()
	persistRecord(record, redactMatch.Count)
}

func persistRecord(record *evidence.EvidenceRecord, redactCount int) {
	if err := evidence.Validate(*record); err != nil {
		log.Printf("EVIDENCE VALIDATION ERROR: %v", err)
	}
	if err := evidenceLedger.Append(record); err != nil {
		log.Printf("EVIDENCE LEDGER ERROR: %v", err)
	}
	data, _ := json.Marshal(record)
	log.Printf("EVIDENCE: %s", string(data))
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string)
	for k, vs := range h {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
