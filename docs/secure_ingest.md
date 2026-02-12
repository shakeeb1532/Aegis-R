# Secure Ingest (Phase 1)

Aegis-R supports a DCF-inspired secure ingest envelope to protect event batches in transit and at rest.

## Envelope
- Compression: `auto | none | lz4`
- Cipher: `AES-256-GCM`
- Integrity: HMAC-SHA256
- Self-describing metadata (version, policy, risk, payload hash)

## Key Generation
```bash
go run ./cmd/aegisr ingest secure-keygen -out data/ingest_keys.json
```

## Pack
```bash
go run ./cmd/aegisr ingest secure-pack \
  -in events.json \
  -out events.aegis \
  -enc-key <b64> \
  -hmac-key <b64> \
  -compress auto \
  -policy adaptive \
  -risk medium
```

## Unpack + Verify
```bash
go run ./cmd/aegisr ingest secure-unpack \
  -in events.aegis \
  -out events.json \
  -enc-key <b64> \
  -hmac-key <b64>
```

## Notes
- HMAC validation is mandatory; invalid envelopes are rejected.
- Compression is applied before encryption.
- Phase 2 will add hybrid key wrapping and signed metadata.
