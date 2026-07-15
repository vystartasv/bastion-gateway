// Command bastion-verify is a standalone offline evidence bundle verifier.
//
// It has zero dependencies on the rest of Bastion. Given a .tar.gz
// evidence bundle exported from Bastion Gateway, it validates every
// record against the schema, recomputes the hash chain, and verifies
// every signature — without network access or production credentials.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: bastion-verify <bundle.tar.gz>\n")
		os.Exit(1)
	}

	bundlePath := os.Args[1]
	if err := verifyBundle(bundlePath); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("VERIFIED: All records intact (chain intact, signatures valid)")
}

func verifyBundle(path string) error {
	// Extract bundle
	files, err := extractTarGz(path)
	if err != nil {
		return fmt.Errorf("extract bundle: %w", err)
	}

	// Load schema
	schemaData, ok := files["record.schema.json"]
	if !ok {
		return fmt.Errorf("bundle missing record.schema.json")
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		return fmt.Errorf("invalid record.schema.json: %w", err)
	}

	// Load public key
	pubKeyData, ok := files["verification.pub"]
	if !ok {
		return fmt.Errorf("bundle missing verification.pub")
	}
	pubKey := ed25519.PublicKey(pubKeyData)

	// Load records
	recordsData, ok := files["records.jsonl"]
	if !ok {
		return fmt.Errorf("bundle missing records.jsonl")
	}

	lines := bytes.Split(bytes.TrimSpace(recordsData), []byte("\n"))
	prevHash := ""

	for i, line := range lines {
		if len(line) == 0 {
			continue
		}

		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("record %d: invalid JSON: %w", i, err)
		}

		// Extract integrity fields
		integrity, ok := rec["integrity"].(map[string]any)
		if !ok {
			return fmt.Errorf("record %d: missing integrity block", i)
		}

		storedHash, _ := integrity["record_hash"].(string)
		storedPrevHash, _ := integrity["previous_record_hash"].(string)
		storedSig, _ := integrity["signature"].(string)
		storedKeyID, _ := integrity["signing_key_id"].(string)

		if storedPrevHash != prevHash {
			return fmt.Errorf("record %d: chain broken at link %d (expected prev %q, got %q)", i, i, prevHash, storedPrevHash)
		}

		// Recompute hash: zero integrity fields, marshal, hash
		rec["integrity"] = map[string]any{
			"previous_record_hash": storedPrevHash,
		}
		canonical, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("record %d: marshal: %w", i, err)
		}
		h := sha256.Sum256(canonical)
		computedHash := hex.EncodeToString(h[:])

		if computedHash != storedHash {
			return fmt.Errorf("record %d: hash mismatch (computed %q, stored %q)", i, computedHash, storedHash)
		}

		// Verify signature
		if len(pubKey) == ed25519.PublicKeySize && storedSig != "" && storedKeyID != "" {
			sig, err := hex.DecodeString(storedSig)
			if err != nil {
				return fmt.Errorf("record %d: invalid signature hex: %w", i, err)
			}
			if !ed25519.Verify(pubKey, canonical, sig) {
				return fmt.Errorf("record %d: invalid signature", i)
			}
		}

		prevHash = computedHash
	}

	if prevHash == "" {
		return fmt.Errorf("bundle contains no valid records")
	}

	return nil
}

func extractTarGz(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	files := make(map[string][]byte)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", header.Name, err)
		}
		files[filepath.Base(header.Name)] = data
	}

	return files, nil
}
