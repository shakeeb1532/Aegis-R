package audit

import "testing"

func TestSignArtifact(t *testing.T) {
	pub, priv, err := GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	a := Artifact{ID: "a1", Summary: "s"}
	s, err := SignArtifact(a, "signer", pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifySignedArtifact(s); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
