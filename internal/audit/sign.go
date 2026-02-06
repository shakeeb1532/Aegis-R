package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type SignedArtifact struct {
	Artifact  Artifact `json:"artifact"`
	SignerID  string   `json:"signer_id"`
	Signature string   `json:"signature"`
	PublicKey string   `json:"public_key"`
}

func GenerateSigningKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

func SignArtifact(a Artifact, signerID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (SignedArtifact, error) {
	payload := struct {
		Artifact Artifact `json:"artifact"`
		SignerID string   `json:"signer_id"`
	}{Artifact: a, SignerID: signerID}
	data, err := json.Marshal(payload)
	if err != nil {
		return SignedArtifact{}, err
	}
	sig := ed25519.Sign(priv, data)
	return SignedArtifact{
		Artifact:  a,
		SignerID:  signerID,
		Signature: base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

func VerifySignedArtifact(s SignedArtifact) error {
	pubBytes, err := base64.StdEncoding.DecodeString(s.PublicKey)
	if err != nil {
		return errors.New("invalid public key encoding")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	payload := struct {
		Artifact Artifact `json:"artifact"`
		SignerID string   `json:"signer_id"`
	}{Artifact: s.Artifact, SignerID: s.SignerID}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return errors.New("artifact signature verification failed")
	}
	return nil
}
