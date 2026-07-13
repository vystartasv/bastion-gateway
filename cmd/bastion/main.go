package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vystartasv/bastion-gateway/internal/approval"
	"github.com/vystartasv/bastion-gateway/internal/audit"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: bastion approve <id> | deny <id> | list | export | genkey <path>\n")
		os.Exit(1)
	}

	approvalDir := getEnv("APPROVAL_DIR", "/var/bastion/approvals")
	auditDir := getEnv("AUDIT_DIR", "/var/bastion/audit")

	switch os.Args[1] {
	case "approve":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: bastion approve <request_id>")
			os.Exit(1)
		}
		s, err := approval.NewStore(approvalDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		req, err := s.Approve(os.Args[2], "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		data, _ := json.MarshalIndent(req, "", "  ")
		fmt.Println(string(data))

	case "deny":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: bastion deny <request_id>")
			os.Exit(1)
		}
		s, err := approval.NewStore(approvalDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := s.Deny(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Denied %s\n", os.Args[2])

	case "list":
		s, err := approval.NewStore(approvalDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		reqs := s.List()
		fmt.Printf("%-36s %-20s %-10s %s\n", "ID", "Agent", "Status", "Created")
		fmt.Println(strings.Repeat("-", 85))
		for _, r := range reqs {
			fmt.Printf("%-36s %-20s %-10s %s\n", r.RequestID, r.AgentID, r.Status, r.CreatedAt)
		}

	case "export":
		s, err := audit.NewStore(auditDir, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		records, err := s.Export()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, r := range records {
			data, _ := json.Marshal(r)
			fmt.Println(string(data))
		}

	case "genkey":
		path := "signing.key"
		if len(os.Args) >= 3 {
			path = os.Args[2]
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, priv, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("Key written to %s\nPublic key: %s\n", path, hex.EncodeToString(pub))

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
