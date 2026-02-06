package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type Approval struct {
	ID           string    `json:"id"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	OktaVerified bool      `json:"okta_verified"`
	SignerID     string    `json:"signer_id"`
	SignerRole   string    `json:"signer_role"`
	PublicKey    string    `json:"public_key"`
	Signature    string    `json:"signature"`
}

type DualApproval struct {
	Approvals   []Approval `json:"approvals"`
	MinSigners  int        `json:"min_signers"`
	RequireOkta bool       `json:"require_okta"`
}

type Payload struct {
	ID           string    `json:"id"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	OktaVerified bool      `json:"okta_verified"`
	SignerID     string    `json:"signer_id"`
	SignerRole   string    `json:"signer_role"`
	PublicKey    string    `json:"public_key"`
}

func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

func Sign(id string, ttl time.Duration, oktaVerified bool, signerID string, signerRole string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (Approval, error) {
	issued := time.Now().UTC()
	expires := issued.Add(ttl)
	payload := Payload{
		ID:           id,
		IssuedAt:     issued,
		ExpiresAt:    expires,
		OktaVerified: oktaVerified,
		SignerID:     signerID,
		SignerRole:   signerRole,
		PublicKey:    base64.StdEncoding.EncodeToString(pub),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return Approval{}, err
	}
	sig := ed25519.Sign(priv, data)
	return Approval{
		ID:           payload.ID,
		IssuedAt:     payload.IssuedAt,
		ExpiresAt:    payload.ExpiresAt,
		OktaVerified: payload.OktaVerified,
		SignerID:     payload.SignerID,
		SignerRole:   payload.SignerRole,
		PublicKey:    payload.PublicKey,
		Signature:    base64.StdEncoding.EncodeToString(sig),
	}, nil
}

func Verify(a Approval, requireOkta bool, now time.Time) error {
	if requireOkta && !a.OktaVerified {
		return errors.New("okta verification required")
	}
	if now.After(a.ExpiresAt) {
		return errors.New("approval expired")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil {
		return errors.New("invalid public key encoding")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	payload := Payload{
		ID:           a.ID,
		IssuedAt:     a.IssuedAt,
		ExpiresAt:    a.ExpiresAt,
		OktaVerified: a.OktaVerified,
		SignerID:     a.SignerID,
		SignerRole:   a.SignerRole,
		PublicKey:    a.PublicKey,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return errors.New("signature verification failed")
	}
	return nil
}

func VerifySignerRole(a Approval, allowedRoles []string) error {
	if len(allowedRoles) == 0 {
		return nil
	}
	for _, r := range allowedRoles {
		if a.SignerRole == r {
			return nil
		}
	}
	return errors.New("signer role not permitted")
}

func VerifyDual(d DualApproval, now time.Time) error {
	if d.MinSigners <= 0 {
		d.MinSigners = 2
	}
	valid := 0
	unique := map[string]bool{}
	for _, a := range d.Approvals {
		if err := Verify(a, d.RequireOkta, now); err == nil {
			key := a.SignerID
			if key == "" {
				key = a.PublicKey
			}
			if !unique[key] {
				unique[key] = true
				valid++
			}
		}
	}
	if valid < d.MinSigners {
		return errors.New("insufficient valid approvals")
	}
	return nil
}
