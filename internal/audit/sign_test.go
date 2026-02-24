package audit

import "testing"

func TestSignArtifact(t *testing.T) {
	ResetTrustedSigners()
	pub, priv, err := GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	a := Artifact{ID: "a1", Summary: "s"}
	s, err := SignArtifact(a, "signer", pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := RegisterTrustedSigner("signer", pub); err != nil {
		t.Fatalf("register signer: %v", err)
	}
	if err := VerifySignedArtifact(s); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
