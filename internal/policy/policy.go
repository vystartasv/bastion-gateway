package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Decision string

const (
	Allow Decision = "ALLOW"
	Deny  Decision = "DENY"
	Hold  Decision = "HOLD"
)

type Policy struct {
	Default string            `yaml:"default"`
	Redact  []RedactRule      `yaml:"redact"`
	Agents  map[string]*Agent `yaml:"agents"`
}

type RedactRule struct {
	Type   string `yaml:"type"`
	Pattern string `yaml:"pattern,omitempty"`
	Name   string `yaml:"name,omitempty"`
}

type Agent struct {
	TrustMin int        `yaml:"trust_min,omitempty"`
	Allow    []string   `yaml:"allow"`
	Hold     []string   `yaml:"hold"`
}

type RuleMatch struct {
	Rule     string
	Decision Decision
	AgentID  string
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid policy yaml: %w", err)
	}
	dflt := strings.ToLower(p.Default)
	if dflt != "deny" && dflt != "allow" {
		return nil, fmt.Errorf("policy default must be 'deny' or 'allow', got %q", p.Default)
	}
	if dflt != "deny" {
		return nil, fmt.Errorf("production policy must default to deny; got %q", p.Default)
	}
	return &p, nil
}

func (p *Policy) Evaluate(agentID, method, host, path string) *RuleMatch {
	agent, ok := p.Agents[agentID]
	if !ok {
		return &RuleMatch{Decision: Deny, AgentID: agentID}
	}

	// Check hold rules first (highest precedence)
	for _, rule := range agent.Hold {
		if match(rule, method, host, path) {
			return &RuleMatch{Rule: rule, Decision: Hold, AgentID: agentID}
		}
	}

	// Check allow rules
	for _, rule := range agent.Allow {
		if match(rule, method, host, path) {
			return &RuleMatch{Rule: rule, Decision: Allow, AgentID: agentID}
		}
	}

	return &RuleMatch{Decision: Deny, AgentID: agentID}
}

func match(rule, method, host, path string) bool {
	parts := strings.Fields(rule)
	if len(parts) < 2 {
		return false
	}
	rMethod := parts[0]
	rTarget := parts[1]

	if rMethod != "*" && !strings.EqualFold(rMethod, method) {
		return false
	}

	return globMatch(rTarget, host+path)
}

func globMatch(pattern, target string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == target
	}
	idx := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			if !strings.HasPrefix(target, part) {
				return false
			}
			idx = len(part)
		} else if i == len(parts)-1 {
			if !strings.HasSuffix(target, part) {
				return false
			}
		} else {
			n := strings.Index(target[idx:], part)
			if n < 0 {
				return false
			}
			idx += n + len(part)
		}
	}
	return true
}

func FindPolicyPath() (string, error) {
	candidates := []string{
		"/policy.yaml",
		"/etc/bastion/policy.yaml",
		"./policy.yaml",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs, nil
		}
	}
	return "", fmt.Errorf("no policy.yaml found in: %s", strings.Join(candidates, ", "))
}
