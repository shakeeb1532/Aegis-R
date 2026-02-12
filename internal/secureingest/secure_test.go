package secureingest

import (
	"encoding/base64"
	"testing"
)

func TestPackUnpackRoundtrip(t *testing.T) {
	enc, err := GenerateKey(32)
	if err != nil {
		t.Fatal(err)
	}
	hmacKey, err := GenerateKey(32)
	if err != nil {
		t.Fatal(err)
	}
	encBytes, _ := base64.StdEncoding.DecodeString(enc)
	hmacBytes, _ := base64.StdEncoding.DecodeString(hmacKey)
	payload := []byte("{\"event\":\"okta_login\"}")
	env, err := Pack(payload, Options{EncKey: encBytes, HMACKey: hmacBytes, Compress: CompressionAuto})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := Unpack(env, Options{EncKey: encBytes, HMACKey: hmacBytes})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(payload) {
		t.Fatalf("roundtrip mismatch: got %s", string(out))
	}
}

func TestHMACMismatch(t *testing.T) {
	enc, _ := GenerateKey(32)
	hmacKey, _ := GenerateKey(32)
	encBytes, _ := base64.StdEncoding.DecodeString(enc)
	hmacBytes, _ := base64.StdEncoding.DecodeString(hmacKey)
	payload := []byte("{\"event\":\"okta_login\"}")
	env, err := Pack(payload, Options{EncKey: encBytes, HMACKey: hmacBytes, Compress: CompressionNone})
	if err != nil {
		t.Fatal(err)
	}
	badKey, _ := GenerateKey(32)
	badBytes, _ := base64.StdEncoding.DecodeString(badKey)
	_, _, err = Unpack(env, Options{EncKey: encBytes, HMACKey: badBytes})
	if err == nil {
		t.Fatal("expected hmac failure")
	}
}
