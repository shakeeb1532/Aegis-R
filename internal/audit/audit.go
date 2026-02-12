package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"aman/internal/compress"
	"aman/internal/ops"
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
	var last string
	if err := forEachAuditLine(path, func(line []byte) error {
		text := strings.TrimSpace(string(line))
		if text == "" {
			return nil
		}
		last = text
		return nil
	}); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
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
	return appendAuditBytes(path, data)
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
	return appendAuditBytes(path, data)
}

func VerifyChain(path string) error {
	if path == "" {
		return nil
	}
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	prevHash := ""
	if err := forEachAuditLine(path, func(line []byte) error {
		text := strings.TrimSpace(string(line))
		if text == "" {
			return nil
		}
		var a Artifact
		if err := json.Unmarshal([]byte(text), &a); err != nil {
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
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func ExportLog(path string, out io.Writer) error {
	if path == "" {
		return nil
	}
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	return forEachAuditLine(path, func(line []byte) error {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			return nil
		}
		_, err := out.Write([]byte(trimmed + "\n"))
		return err
	})
}

func FindArtifact(path string, id string) (Artifact, error) {
	if path == "" {
		return Artifact{}, os.ErrInvalid
	}
	if !ops.IsSafePath(path) {
		return Artifact{}, os.ErrInvalid
	}
	var found Artifact
	err := forEachAuditLine(path, func(line []byte) error {
		text := strings.TrimSpace(string(line))
		if text == "" {
			return nil
		}
		var a Artifact
		if err := json.Unmarshal([]byte(text), &a); err != nil {
			return nil
		}
		if a.ID == id {
			found = a
			return io.EOF
		}
		return nil
	})
	if errors.Is(err, io.EOF) {
		return found, nil
	}
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{}, errors.New("decision not found")
}

func forEachAuditLine(path string, fn func([]byte) error) error {
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if strings.HasSuffix(path, ".lz4") {
		reader := bufio.NewReader(f)
		for {
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(reader, lenBuf); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				if errors.Is(err, io.ErrUnexpectedEOF) {
					return errors.New("audit log corrupted: unexpected EOF")
				}
				return err
			}
			n := binary.LittleEndian.Uint32(lenBuf)
			if n == 0 {
				continue
			}
			payload := make([]byte, n)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return err
			}
			decoded, err := compress.Decompress(payload)
			if err != nil {
				return err
			}
			if err := fn(decoded); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := fn(scanner.Bytes()); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
	return scanner.Err()
}

func appendAuditBytes(path string, data []byte) error {
	if strings.HasSuffix(path, ".lz4") {
		compressed, err := compress.Compress(data)
		if err != nil {
			return err
		}
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(compressed)))
		//nolint:gosec // path validated via IsSafePath
		// #nosec G304
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		if _, err := f.Write(lenBuf); err != nil {
			return err
		}
		_, err = f.Write(compressed)
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
