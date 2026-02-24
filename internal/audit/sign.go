package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

type SignedArtifact struct {
	Artifact  Artifact `json:"artifact"`
	SignerID  string   `json:"signer_id"`
	SignedAt  time.Time `json:"signed_at"`
	KeyID     string   `json:"key_id"`
	Signature string   `json:"signature"`
	PublicKey string   `json:"public_key"`
}

var (
	trustedSignerMu   sync.RWMutex
	trustedSignerKeys = map[string]string{}
)

func GenerateSigningKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

func SignArtifact(a Artifact, signerID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (SignedArtifact, error) {
	if signerID == "" {
		return SignedArtifact{}, errors.New("signer_id is required")
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	now := time.Now().UTC()
	payload := struct {
		Artifact Artifact `json:"artifact"`
		SignerID string   `json:"signer_id"`
		SignedAt time.Time `json:"signed_at"`
		KeyID    string   `json:"key_id"`
	}{Artifact: a, SignerID: signerID, SignedAt: now, KeyID: signerID + ":ed25519:v1"}
	data, err := json.Marshal(payload)
	if err != nil {
		return SignedArtifact{}, err
	}
	sig := ed25519.Sign(priv, data)
	return SignedArtifact{
		Artifact:  a,
		SignerID:  signerID,
		SignedAt:  now,
		KeyID:     payload.KeyID,
		Signature: base64.StdEncoding.EncodeToString(sig),
		PublicKey: pubB64,
	}, nil
}

func VerifySignedArtifact(s SignedArtifact) error {
	if s.SignerID == "" {
		return errors.New("missing signer_id")
	}
	trustedSignerMu.RLock()
	trustedPub, ok := trustedSignerKeys[s.SignerID]
	trustedSignerMu.RUnlock()
	if !ok {
		return fmt.Errorf("untrusted signer: %s", s.SignerID)
	}
	if trustedPub != s.PublicKey {
		return errors.New("public key mismatch for signer")
	}
	return verifySignedArtifactWithPublicKey(s, trustedPub)
}

func verifySignedArtifactWithPublicKey(s SignedArtifact, trustedPublicKeyB64 string) error {
	pubBytes, err := base64.StdEncoding.DecodeString(s.PublicKey)
	if err != nil {
		return errors.New("invalid public key encoding")
	}
	if trustedPublicKeyB64 != "" && trustedPublicKeyB64 != s.PublicKey {
		return errors.New("provided trusted key does not match artifact key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	payload := struct {
		Artifact Artifact `json:"artifact"`
		SignerID string   `json:"signer_id"`
		SignedAt time.Time `json:"signed_at"`
		KeyID    string   `json:"key_id"`
	}{Artifact: s.Artifact, SignerID: s.SignerID, SignedAt: s.SignedAt, KeyID: s.KeyID}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return errors.New("artifact signature verification failed")
	}
	return nil
}

func RegisterTrustedSigner(signerID string, publicKey ed25519.PublicKey) error {
	if signerID == "" {
		return errors.New("signer_id is required")
	}
	if len(publicKey) == 0 {
		return errors.New("public key is required")
	}
	trustedSignerMu.Lock()
	defer trustedSignerMu.Unlock()
	trustedSignerKeys[signerID] = base64.StdEncoding.EncodeToString(publicKey)
	return nil
}

func ResetTrustedSigners() {
	trustedSignerMu.Lock()
	defer trustedSignerMu.Unlock()
	trustedSignerKeys = map[string]string{}
}
