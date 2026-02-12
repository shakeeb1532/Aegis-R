package secureingest

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateKey(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
