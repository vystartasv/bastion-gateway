package redact

import (
	"regexp"
)

type Match struct {
	Type   string
	Count  int
}

type Engine struct {
	rules []Rule
}

type Rule struct {
	Type    string
	Pattern *regexp.Regexp
	Name    string
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

var builtins = map[string]*regexp.Regexp{
	"bearer":          regexp.MustCompile(`(?i)bearer\s+[a-z0-9._\-+/=]{8,}`),
	"jwt":             regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	"email":           regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	"aws_key":         regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
	"private_key_block": regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----`),
}

func NewRegexp(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

func BuiltinRules(names []string) []Rule {
	var rules []Rule
	for _, n := range names {
		if re, ok := builtins[n]; ok {
			rules = append(rules, Rule{Name: n, Pattern: re})
		}
	}
	return rules
}

func (e *Engine) Apply(body []byte) ([]byte, *Match) {
	s := string(body)
	total := 0
	for _, rule := range e.rules {
		matches := rule.Pattern.FindAllString(s, -1)
		if len(matches) == 0 {
			continue
		}
		total += len(matches)
		replacement := "<redacted:" + rule.Name + ">"
		s = rule.Pattern.ReplaceAllString(s, replacement)
	}
	return []byte(s), &Match{Count: total}
}

func ParseRedactRules(rules []Rule) *Engine {
	return NewEngine(rules)
}
