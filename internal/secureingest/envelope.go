package secureingest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"aman/internal/compress"
)

const (
	CompressionAuto = "auto"
	CompressionNone = "none"
	CompressionLZ4  = "lz4"
)

const CipherAESGCM = "AES-256-GCM"

const Version = "v1"

var (
	ErrHMACVerify   = errors.New("hmac verification failed")
	ErrDecrypt      = errors.New("decrypt failed")
	ErrPayloadHash  = errors.New("payload hash mismatch")
	ErrKeyLength    = errors.New("enc key must be 32 bytes")
	ErrHMACKeyShort = errors.New("hmac key too short")
)

type Envelope struct {
	Version     string `json:"version"`
	CreatedAt   string `json:"created_at"`
	Compression string `json:"compression"`
	Cipher      string `json:"cipher"`
	Policy      string `json:"policy"`
	Risk        string `json:"risk"`
	PayloadHash string `json:"payload_hash"`
	Nonce       string `json:"nonce"`
	Payload     string `json:"payload"`
	HMAC        string `json:"hmac"`
}

type Options struct {
	EncKey     []byte
	HMACKey    []byte
	Policy     string
	Risk       string
	Compress   string
	CreatedAt  time.Time
	ForceNoGCM bool
}

func Pack(payload []byte, opts Options) ([]byte, error) {
	if len(opts.EncKey) != 32 {
		return nil, ErrKeyLength
	}
	if len(opts.HMACKey) < 16 {
		return nil, ErrHMACKeyShort
	}
	if opts.Policy == "" {
		opts.Policy = "adaptive"
	}
	if opts.Risk == "" {
		opts.Risk = "medium"
	}
	created := opts.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}

	comp := chooseCompression(payload, opts.Compress)
	compressed := payload
	if comp == CompressionLZ4 {
		var err error
		compressed, err = compress.Compress(payload)
		if err != nil {
			return nil, err
		}
	}
	hash := sha256.Sum256(payload)

	block, err := aes.NewCipher(opts.EncKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := aadString(Version, comp, CipherAESGCM, opts.Policy, opts.Risk, hex.EncodeToString(hash[:]))
	ciphertext := gcm.Seal(nil, nonce, compressed, []byte(aad))

	env := Envelope{
		Version:     Version,
		CreatedAt:   created.Format(time.RFC3339),
		Compression: comp,
		Cipher:      CipherAESGCM,
		Policy:      opts.Policy,
		Risk:        opts.Risk,
		PayloadHash: hex.EncodeToString(hash[:]),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Payload:     base64.StdEncoding.EncodeToString(ciphertext),
	}
	env.HMAC = computeHMAC(env, opts.HMACKey)
	return json.MarshalIndent(env, "", "  ")
}

func Unpack(data []byte, opts Options) ([]byte, Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, env, err
	}
	if env.Version != Version {
		return nil, env, fmt.Errorf("unsupported version: %s", env.Version)
	}
	if len(opts.EncKey) != 32 {
		return nil, env, ErrKeyLength
	}
	if len(opts.HMACKey) < 16 {
		return nil, env, ErrHMACKeyShort
	}
	expected := computeHMAC(env, opts.HMACKey)
	if !hmac.Equal([]byte(env.HMAC), []byte(expected)) {
		return nil, env, ErrHMACVerify
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, env, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, env, err
	}
	block, err := aes.NewCipher(opts.EncKey)
	if err != nil {
		return nil, env, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, env, err
	}
	aad := aadString(env.Version, env.Compression, env.Cipher, env.Policy, env.Risk, env.PayloadHash)
	compressed, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, env, ErrDecrypt
	}
	out := compressed
	if env.Compression == CompressionLZ4 {
		out, err = compress.Decompress(compressed)
		if err != nil {
			return nil, env, ErrDecrypt
		}
	}
	hash := sha256.Sum256(out)
	if !strings.EqualFold(hex.EncodeToString(hash[:]), env.PayloadHash) {
		return nil, env, ErrPayloadHash
	}
	return out, env, nil
}

func UnpackWithKeyring(data []byte, opts []Options) ([]byte, Envelope, error) {
	var lastErr error
	for _, o := range opts {
		payload, env, err := Unpack(data, o)
		if err == nil {
			return payload, env, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrDecrypt
	}
	return nil, Envelope{}, lastErr
}

func chooseCompression(payload []byte, mode string) string {
	if mode == "" {
		mode = CompressionAuto
	}
	switch mode {
	case CompressionNone:
		return CompressionNone
	case CompressionLZ4:
		return CompressionLZ4
	default:
		if len(payload) >= 32*1024 {
			return CompressionLZ4
		}
		return CompressionNone
	}
}

func computeHMAC(env Envelope, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(aadString(env.Version, env.Compression, env.Cipher, env.Policy, env.Risk, env.PayloadHash)))
	mac.Write([]byte("\n" + env.Nonce))
	mac.Write([]byte("\n" + env.Payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func aadString(fields ...string) string {
	return strings.Join(fields, "|")
}
