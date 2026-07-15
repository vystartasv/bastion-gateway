package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// IdentityResolver maps agent IDs and bearer tokens to structured identities.
type IdentityResolver struct {
	mappingPath      string
	requirePrincipal bool
	tokenMap         map[string]tokenIdentity
}

type tokenIdentity struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// NewIdentityResolver creates a resolver. If mappingPath is empty, no token-to-human mapping is loaded.
func NewIdentityResolver(mappingPath string, requirePrincipal bool) *IdentityResolver {
	r := &IdentityResolver{
		mappingPath:      mappingPath,
		requirePrincipal: requirePrincipal,
		tokenMap:         make(map[string]tokenIdentity),
	}
	if mappingPath != "" {
		data, err := os.ReadFile(mappingPath)
		if err == nil {
			json.Unmarshal(data, &r.tokenMap)
		}
	}
	return r
}

// ResolveResult holds the resolved identity and any blocking error.
type ResolveResult struct {
	Identity Identity
	Err      error
}

// Resolve maps an agentID + optional bearer token to an Identity.
func (r *IdentityResolver) Resolve(agentID, bearerToken string) ResolveResult {
	// Try bearer token mapping first
	if bearerToken != "" && len(r.tokenMap) > 0 {
		h := sha256.Sum256([]byte(bearerToken))
		tokenKey := hex.EncodeToString(h[:])
		if mapped, ok := r.tokenMap[tokenKey]; ok {
			return ResolveResult{
				Identity: Identity{
					Principal: Principal{
						Name: mapped.Name,
						Type: "human",
					},
					AuthMethod: "bearer",
					Role:       mapped.Role,
				},
			}
		}
	}

	// Fall back to agent ID from header
	if agentID == "" || agentID == "unknown" {
		if r.requirePrincipal {
			return ResolveResult{Err: fmt.Errorf("unattributed request")}
		}
		return ResolveResult{
			Identity: Identity{
				Principal: Principal{
					Name: "unknown",
					Type: "delegated",
				},
				AuthMethod: "none",
				Role:       "unknown",
			},
		}
	}

	// Sanitize: svc-/bot- prefix with delegated type
	typ := "delegated"
	name := agentID
	if strings.HasPrefix(agentID, "svc-") || strings.HasPrefix(agentID, "bot-") {
		typ = "delegated" // legitimate service accounts stay delegated
	}

	return ResolveResult{
		Identity: Identity{
			Principal: Principal{
				Name: name,
				Type: typ,
			},
			AuthMethod: "header",
			Role:       "agent",
		},
	}
}
