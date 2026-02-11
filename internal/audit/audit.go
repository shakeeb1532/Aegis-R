package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"aegisr/internal/ops"
)

type Artifact struct {
	ID        string            `json:"id"`
	CreatedAt time.Time         `json:"created_at"`
	Summary   string            `json:"summary"`
	Findings  []string          `json:"findings"`
	Reasoning []string          `json:"reasoning"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
	Metadata  map[string]string `json:"metadata"`
}

func HashArtifact(a Artifact) (string, error) {
	clone := a
	clone.Hash = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func LoadLastHash(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if !ops.IsSafePath(path) {
		return "", os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer func() { _ = f.Close() }()

	var last string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		last = line
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if last == "" {
		return "", nil
	}
	var a Artifact
	if err := json.Unmarshal([]byte(last), &a); err != nil {
		return "", err
	}
	return a.Hash, nil
}

func AppendLog(path string, a Artifact) error {
	if path == "" {
		return nil
	}
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(data)
	return err
}

func AppendSigned(path string, s SignedArtifact) error {
	if path == "" {
		return nil
	}
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(data)
	return err
}

func VerifyChain(path string) error {
	if path == "" {
		return nil
	}
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	prevHash := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var a Artifact
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return err
		}
		if a.PrevHash != prevHash {
			return errors.New("audit chain broken: prev hash mismatch")
		}
		expected, err := HashArtifact(a)
		if err != nil {
			return err
		}
		if a.Hash != expected {
			return errors.New("audit chain broken: hash mismatch")
		}
		prevHash = a.Hash
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
