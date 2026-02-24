package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndVerifyEvidenceBundle(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.log")
	approvalsPath := filepath.Join(tmp, "approvals.log")
	if err := os.WriteFile(auditPath, []byte("{\"id\":\"a1\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(approvalsPath, []byte("{\"id\":\"p1\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(tmp, "evidence.zip")
	manifest, err := CreateEvidenceBundle(BundleOptions{
		OutputPath: bundlePath,
		Inputs: map[string]string{
			"audit":     auditPath,
			"approvals": approvalsPath,
		},
		Inline: map[string][]byte{
			"controls.json": []byte(`{"ok":true}`),
		},
		Signer:     "auditor",
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Signature == "" {
		t.Fatal("expected signature")
	}
	result, err := VerifyEvidenceBundle(bundlePath, "")
	if err != nil {
		t.Fatal(err)
	}
	if !result.DigestValid || !result.SignatureValid {
		t.Fatalf("expected valid bundle, got %+v", result)
	}
}

func TestVerifyUnsignedEvidenceBundle(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.log")
	if err := os.WriteFile(auditPath, []byte("{\"id\":\"a1\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(tmp, "unsigned.zip")
	_, err := CreateEvidenceBundle(BundleOptions{
		OutputPath: bundlePath,
		Inputs: map[string]string{
			"audit": auditPath,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyEvidenceBundle(bundlePath, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.SignaturePresent || result.SignatureValid {
		t.Fatalf("expected unsigned bundle result, got %+v", result)
	}
}

func TestCreateEvidenceBundleReproducible(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.log")
	if err := os.WriteFile(auditPath, []byte("{\"id\":\"a1\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out1 := filepath.Join(tmp, "a.zip")
	out2 := filepath.Join(tmp, "b.zip")
	opts := BundleOptions{
		Inputs: map[string]string{
			"audit": auditPath,
		},
		Inline: map[string][]byte{
			"controls.json": []byte(`{"x":1}`),
		},
		Reproducible: true,
	}
	opts.OutputPath = out1
	if _, err := CreateEvidenceBundle(opts); err != nil {
		t.Fatal(err)
	}
	opts.OutputPath = out2
	if _, err := CreateEvidenceBundle(opts); err != nil {
		t.Fatal(err)
	}
	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("expected reproducible bundle bytes to match")
	}
}
