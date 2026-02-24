package audit

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aman/internal/ops"
)

type BundleFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type EvidenceBundleManifest struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Signer      string       `json:"signer,omitempty"`
	PublicKey   string       `json:"public_key,omitempty"`
	Files       []BundleFile `json:"files"`
	Digest      string       `json:"digest"`
	Signature   string       `json:"signature,omitempty"`
}

type BundleOptions struct {
	OutputPath   string
	Inputs       map[string]string
	Inline       map[string][]byte
	Reproducible bool
	Signer       string
	PublicKey    string
	PrivateKey   string
}

type VerifyBundleResult struct {
	FilesVerified    int      `json:"files_verified"`
	DigestValid      bool     `json:"digest_valid"`
	SignaturePresent bool     `json:"signature_present"`
	SignatureValid   bool     `json:"signature_valid"`
	Errors           []string `json:"errors,omitempty"`
}

func CreateEvidenceBundle(opts BundleOptions) (EvidenceBundleManifest, error) {
	if opts.OutputPath == "" {
		return EvidenceBundleManifest{}, errors.New("output path is required")
	}
	if !ops.IsSafePath(opts.OutputPath) {
		return EvidenceBundleManifest{}, os.ErrInvalid
	}
	if len(opts.Inputs) == 0 && len(opts.Inline) == 0 {
		return EvidenceBundleManifest{}, errors.New("at least one input or inline payload is required")
	}
	if opts.PrivateKey != "" && opts.PublicKey == "" {
		return EvidenceBundleManifest{}, errors.New("public key is required when private key is set")
	}

	f, err := os.OpenFile(opts.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return EvidenceBundleManifest{}, err
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	generatedAt := time.Now().UTC()
	if opts.Reproducible {
		generatedAt = time.Unix(0, 0).UTC()
	}
	manifest := EvidenceBundleManifest{GeneratedAt: generatedAt, Signer: strings.TrimSpace(opts.Signer)}
	keys := make([]string, 0, len(opts.Inputs))
	for name := range opts.Inputs {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, logical := range keys {
		src := opts.Inputs[logical]
		if src == "" {
			continue
		}
		if !ops.IsSafePath(src) {
			_ = zw.Close()
			return EvidenceBundleManifest{}, os.ErrInvalid
		}
		data, err := os.ReadFile(src)
		if err != nil {
			_ = zw.Close()
			return EvidenceBundleManifest{}, err
		}
		h := sha256.Sum256(data)
		entryName := filepath.ToSlash(filepath.Join("evidence", logical+"-"+filepath.Base(src)))
		w, err := createZipEntry(zw, entryName, opts.Reproducible)
		if err != nil {
			_ = zw.Close()
			return EvidenceBundleManifest{}, err
		}
		if _, err := w.Write(data); err != nil {
			_ = zw.Close()
			return EvidenceBundleManifest{}, err
		}
		manifest.Files = append(manifest.Files, BundleFile{
			Name:   entryName,
			SHA256: hex.EncodeToString(h[:]),
			Bytes:  int64(len(data)),
		})
	}
	inlineKeys := make([]string, 0, len(opts.Inline))
	for name := range opts.Inline {
		inlineKeys = append(inlineKeys, name)
	}
	sort.Strings(inlineKeys)
	for _, logical := range inlineKeys {
		data := opts.Inline[logical]
		if len(data) == 0 {
			continue
		}
		h := sha256.Sum256(data)
		entryName := filepath.ToSlash(filepath.Join("evidence", logical))
		w, err := createZipEntry(zw, entryName, opts.Reproducible)
		if err != nil {
			_ = zw.Close()
			return EvidenceBundleManifest{}, err
		}
		if _, err := w.Write(data); err != nil {
			_ = zw.Close()
			return EvidenceBundleManifest{}, err
		}
		manifest.Files = append(manifest.Files, BundleFile{
			Name:   entryName,
			SHA256: hex.EncodeToString(h[:]),
			Bytes:  int64(len(data)),
		})
	}

	digest, err := computeManifestDigest(manifest)
	if err != nil {
		_ = zw.Close()
		return EvidenceBundleManifest{}, err
	}
	manifest.Digest = digest
	if opts.PrivateKey != "" {
		privRaw, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
		if err != nil {
			_ = zw.Close()
			return EvidenceBundleManifest{}, err
		}
		pubRaw, err := base64.StdEncoding.DecodeString(opts.PublicKey)
		if err != nil {
			_ = zw.Close()
			return EvidenceBundleManifest{}, err
		}
		if len(privRaw) != ed25519.PrivateKeySize || len(pubRaw) != ed25519.PublicKeySize {
			_ = zw.Close()
			return EvidenceBundleManifest{}, errors.New("invalid signing key size")
		}
		sig := ed25519.Sign(ed25519.PrivateKey(privRaw), []byte(manifest.Digest))
		manifest.PublicKey = opts.PublicKey
		manifest.Signature = base64.StdEncoding.EncodeToString(sig)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		_ = zw.Close()
		return EvidenceBundleManifest{}, err
	}
	mw, err := createZipEntry(zw, "manifest.json", opts.Reproducible)
	if err != nil {
		_ = zw.Close()
		return EvidenceBundleManifest{}, err
	}
	if _, err := mw.Write(manifestBytes); err != nil {
		_ = zw.Close()
		return EvidenceBundleManifest{}, err
	}
	if err := zw.Close(); err != nil {
		return EvidenceBundleManifest{}, err
	}
	return manifest, nil
}

func VerifyEvidenceBundle(path string, expectedPublicKey string) (VerifyBundleResult, error) {
	if path == "" {
		return VerifyBundleResult{}, errors.New("bundle path is required")
	}
	if !ops.IsSafePath(path) {
		return VerifyBundleResult{}, os.ErrInvalid
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return VerifyBundleResult{}, err
	}
	defer func() { _ = zr.Close() }()
	files := map[string][]byte{}
	var manifest EvidenceBundleManifest
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			return VerifyBundleResult{}, err
		}
		b, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			return VerifyBundleResult{}, err
		}
		if f.Name == "manifest.json" {
			if err := json.Unmarshal(b, &manifest); err != nil {
				return VerifyBundleResult{}, err
			}
			continue
		}
		files[f.Name] = b
	}
	if manifest.GeneratedAt.IsZero() {
		return VerifyBundleResult{}, errors.New("manifest not found")
	}
	res := VerifyBundleResult{DigestValid: true}
	for _, mf := range manifest.Files {
		content, ok := files[mf.Name]
		if !ok {
			res.Errors = append(res.Errors, "missing file: "+mf.Name)
			continue
		}
		h := sha256.Sum256(content)
		if hex.EncodeToString(h[:]) != mf.SHA256 {
			res.Errors = append(res.Errors, "hash mismatch: "+mf.Name)
			continue
		}
		res.FilesVerified++
	}
	expectedDigest, err := computeManifestDigest(EvidenceBundleManifest{
		GeneratedAt: manifest.GeneratedAt,
		Signer:      manifest.Signer,
		Files:       manifest.Files,
	})
	if err != nil {
		return res, err
	}
	if expectedDigest != manifest.Digest {
		res.DigestValid = false
		res.Errors = append(res.Errors, "manifest digest mismatch")
	}
	if manifest.Signature != "" {
		res.SignaturePresent = true
		pub := manifest.PublicKey
		if expectedPublicKey != "" {
			pub = expectedPublicKey
		}
		pubRaw, err := base64.StdEncoding.DecodeString(pub)
		if err != nil || len(pubRaw) != ed25519.PublicKeySize {
			res.SignatureValid = false
			res.Errors = append(res.Errors, "invalid public key")
		} else {
			sigRaw, err := base64.StdEncoding.DecodeString(manifest.Signature)
			if err != nil || !ed25519.Verify(ed25519.PublicKey(pubRaw), []byte(manifest.Digest), sigRaw) {
				res.SignatureValid = false
				res.Errors = append(res.Errors, "signature verification failed")
			} else {
				res.SignatureValid = true
			}
		}
	} else if expectedPublicKey != "" {
		res.Errors = append(res.Errors, "bundle is unsigned but --pubkey was provided")
	}
	if len(res.Errors) > 0 {
		return res, fmt.Errorf("bundle verification failed: %d issue(s)", len(res.Errors))
	}
	return res, nil
}

func computeManifestDigest(m EvidenceBundleManifest) (string, error) {
	clone := m
	clone.Digest = ""
	clone.Signature = ""
	clone.PublicKey = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func createZipEntry(zw *zip.Writer, name string, reproducible bool) (io.Writer, error) {
	if !reproducible {
		return zw.Create(name)
	}
	h := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	h.SetModTime(time.Unix(0, 0).UTC())
	return zw.CreateHeader(h)
}
