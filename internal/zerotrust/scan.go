package zerotrust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aegisr/internal/ops"
)

type Baseline struct {
	CreatedAt time.Time         `json:"created_at"`
	Root      string            `json:"root"`
	Hashes    map[string]string `json:"hashes"`
}

type Result struct {
	Missing []string
	Added   []string
	Changed []string
}

var DefaultExclusions = []string{
	".git/",
	".DS_Store",
	"audit.log",
	"signed_audit.log",
	"approvals.log",
	"state.json",
	"data/scenarios.json",
	"data/scenarios_realistic.json",
}

func BuildBaseline(root string, exclusions []string) (Baseline, error) {
	hashes := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if isExcludedDir(path, root, exclusions) {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if isExcludedFile(rel, exclusions) {
			return nil
		}
		h, err := hashFile(path)
		if err != nil {
			return err
		}
		hashes[filepath.ToSlash(rel)] = h
		return nil
	})
	if err != nil {
		return Baseline{}, err
	}
	return Baseline{CreatedAt: time.Now().UTC(), Root: root, Hashes: hashes}, nil
}

func SaveBaseline(path string, b Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func LoadBaseline(path string) (Baseline, error) {
	if !ops.IsSafePath(path) {
		return Baseline{}, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, err
	}
	if len(b.Hashes) == 0 {
		return Baseline{}, errors.New("baseline empty")
	}
	return b, nil
}

func Compare(root string, baseline Baseline, exclusions []string) (Result, error) {
	current, err := BuildBaseline(root, exclusions)
	if err != nil {
		return Result{}, err
	}
	res := Result{}
	for path, hash := range baseline.Hashes {
		cur, ok := current.Hashes[path]
		if !ok {
			res.Missing = append(res.Missing, path)
			continue
		}
		if cur != hash {
			res.Changed = append(res.Changed, path)
		}
	}
	for path := range current.Hashes {
		if _, ok := baseline.Hashes[path]; !ok {
			res.Added = append(res.Added, path)
		}
	}
	sort.Strings(res.Missing)
	sort.Strings(res.Added)
	sort.Strings(res.Changed)
	return res, nil
}

func hashFile(path string) (string, error) {
	//nolint:gosec // path derived from filesystem walk under trusted root
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isExcludedDir(path string, root string, exclusions []string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel) + "/"
	for _, ex := range exclusions {
		ex = filepath.ToSlash(ex)
		if strings.HasSuffix(ex, "/") && strings.HasPrefix(rel, ex) {
			return true
		}
	}
	return false
}

func isExcludedFile(rel string, exclusions []string) bool {
	rel = filepath.ToSlash(rel)
	for _, ex := range exclusions {
		ex = filepath.ToSlash(ex)
		if strings.HasSuffix(ex, "/") {
			if strings.HasPrefix(rel, ex) {
				return true
			}
			continue
		}
		if rel == ex {
			return true
		}
	}
	return false
}
