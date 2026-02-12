package secureingest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"
)

type Keyring struct {
	EncKey       string `json:"enc_key"`
	HMACKey      string `json:"hmac_key"`
	PrevEncKey   string `json:"prev_enc_key,omitempty"`
	PrevHMACKey  string `json:"prev_hmac_key,omitempty"`
	RotatedAtUTC string `json:"rotated_at_utc,omitempty"`
}

func NewKeyring() (Keyring, error) {
	enc, err := GenerateKey(32)
	if err != nil {
		return Keyring{}, err
	}
	hmacKey, err := GenerateKey(32)
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{EncKey: enc, HMACKey: hmacKey}, nil
}

func LoadKeyring(path string) (Keyring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Keyring{}, err
	}
	var k Keyring
	if err := json.Unmarshal(data, &k); err != nil {
		return Keyring{}, err
	}
	if k.EncKey == "" || k.HMACKey == "" {
		return Keyring{}, errors.New("keyring missing enc_key or hmac_key")
	}
	return k, nil
}

func SaveKeyring(path string, k Keyring) error {
	data, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func RotateKeyring(k Keyring) (Keyring, error) {
	newEnc, err := GenerateKey(32)
	if err != nil {
		return Keyring{}, err
	}
	newHMAC, err := GenerateKey(32)
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{
		EncKey:       newEnc,
		HMACKey:      newHMAC,
		PrevEncKey:   k.EncKey,
		PrevHMACKey:  k.HMACKey,
		RotatedAtUTC: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func KeyringOptions(k Keyring) ([]Options, error) {
	currentEnc, err := base64.StdEncoding.DecodeString(k.EncKey)
	if err != nil {
		return nil, err
	}
	currentHMAC, err := base64.StdEncoding.DecodeString(k.HMACKey)
	if err != nil {
		return nil, err
	}
	opts := []Options{{EncKey: currentEnc, HMACKey: currentHMAC}}
	if k.PrevEncKey != "" && k.PrevHMACKey != "" {
		prevEnc, err := base64.StdEncoding.DecodeString(k.PrevEncKey)
		if err != nil {
			return nil, err
		}
		prevHMAC, err := base64.StdEncoding.DecodeString(k.PrevHMACKey)
		if err != nil {
			return nil, err
		}
		opts = append(opts, Options{EncKey: prevEnc, HMACKey: prevHMAC})
	}
	return opts, nil
}
