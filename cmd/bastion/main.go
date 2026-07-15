package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vystartasv/bastion-gateway/internal/approval"
	"github.com/vystartasv/bastion-gateway/internal/evidence"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: bastion approve <id> | deny <id> | list | export | export-bundle | verify | genkey <path>\n")
		os.Exit(1)
	}

	approvalDir := getEnv("APPROVAL_DIR", "/var/bastion/approvals")
	evidenceDir := getEnv("EVIDENCE_DIR", "/var/bastion/evidence")
	signKeyPath := getEnv("SIGN_KEY", "/var/bastion/signing.key")

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
		signer, err := evidence.NewEd25519Signer(signKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: no signer: %v (unsigned)\n", err)
			signer = nil
		}
		storage, err := evidence.NewFileStorage(evidenceDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		var ledger *evidence.Ledger
		if signer != nil {
			ledger = evidence.NewLedger(storage, signer, evidenceDir)
		} else {
			// Fallback: use testsigner for export-only (no signing)
			ledger = evidence.NewLedger(storage, evidence.NewTestSigner("export"), evidenceDir)
		}

		records, err := ledger.ReadRange(genesisTime(), now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, r := range records {
			data, _ := json.Marshal(r)
			fmt.Println(string(data))
		}

	case "export-bundle":
		outputPath := "evidence-bundle.tar.gz"
		if len(os.Args) >= 3 {
			outputPath = os.Args[2]
		}
		if err := exportBundle(evidenceDir, signKeyPath, outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Bundle written to %s\n", outputPath)

	case "verify":
		signer, err := evidence.NewEd25519Signer(signKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		storage, err := evidence.NewFileStorage(evidenceDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		ledger := evidence.NewLedger(storage, signer, evidenceDir)
		ok, idx, err := ledger.VerifyChain()
		if ok {
			cs := ledger.ChainState()
			fmt.Printf("VERIFIED: All %d records intact (chain intact, signatures valid)\n", cs.RecordCnt)
		} else {
			fmt.Fprintf(os.Stderr, "FAIL: chain broken at record %d: %v\n", idx, err)
			os.Exit(1)
		}

	case "genkey":
		path := "signing.key"
		if len(os.Args) >= 3 {
			path = os.Args[2]
		}
		if err := evidence.GenerateKey(path); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		// Read back to display public key
		signer, err := evidence.NewEd25519Signer(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading generated key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Key written to %s\nKey ID: %s\n", path, signer.KeyID())

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

func genesisTime() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func now() time.Time { return time.Now().UTC() }

func exportBundle(evidenceDir, signKeyPath, outputPath string) error {
	signer, err := evidence.NewEd25519Signer(signKeyPath)
	if err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	storage, err := evidence.NewFileStorage(evidenceDir)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	ledger := evidence.NewLedger(storage, signer, evidenceDir)

	records, err := ledger.ReadRange(genesisTime(), now())
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	// Build JSONL
	var buf bytes.Buffer
	for _, r := range records {
		data, _ := json.Marshal(r)
		buf.Write(data)
		buf.WriteByte('\n')
	}
	recordsJSONL := buf.Bytes()

	// Build VERIFY.md
	verifyMD := `# Evidence Bundle Verification

This bundle contains signed decision records from Bastion Gateway.

## To verify

1. Download the standalone verifier:
   go install github.com/vystartasv/bastion-gateway/cmd/bastion-verify@latest

2. Run:
   bastion-verify evidence-bundle.tar.gz

3. Expected output: VERIFIED: All N records intact (chain intact, signatures valid).

## Bundle contents
- records.jsonl — the evidence records (signed, hash-chained)
- record.schema.json — JSON Schema for validation
- verification.pub — Ed25519 public key for signature verification
- VERIFY.md — this file

No production access, network, or Bastion installation required.
`

	// Write tar.gz
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// records.jsonl
	if err := tw.WriteHeader(&tar.Header{
		Name:     "records.jsonl",
		Size:     int64(len(recordsJSONL)),
		Typeflag: tar.TypeReg,
		Mode:     0644,
	}); err != nil {
		return err
	}
	if _, err := tw.Write(recordsJSONL); err != nil {
		return err
	}

	// record.schema.json
	schemaData := evidence.LoadSchema()
	if err := tw.WriteHeader(&tar.Header{
		Name:     "record.schema.json",
		Size:     int64(len(schemaData)),
		Typeflag: tar.TypeReg,
		Mode:     0644,
	}); err != nil {
		return err
	}
	if _, err := tw.Write(schemaData); err != nil {
		return err
	}

	// verification.pub
	pubKey := signer.Public()
	if err := tw.WriteHeader(&tar.Header{
		Name:     "verification.pub",
		Size:     int64(len(pubKey)),
		Typeflag: tar.TypeReg,
		Mode:     0644,
	}); err != nil {
		return err
	}
	if _, err := tw.Write(pubKey); err != nil {
		return err
	}

	// VERIFY.md
	verifyData := []byte(verifyMD)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "VERIFY.md",
		Size:     int64(len(verifyData)),
		Typeflag: tar.TypeReg,
		Mode:     0644,
	}); err != nil {
		return err
	}
	if _, err := tw.Write(verifyData); err != nil {
		return err
	}

	return nil
}
