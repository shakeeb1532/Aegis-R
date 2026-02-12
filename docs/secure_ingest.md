# Secure Ingest (Phase 1)

Aman supports a DCF-inspired secure ingest envelope to protect event batches in transit and at rest.

## Envelope
- Compression: `auto | none | lz4`
- Cipher: `AES-256-GCM`
- Integrity: HMAC-SHA256
- Self-describing metadata (version, policy, risk, payload hash)

## Quickstart (Keyring + HTTP)
```bash
go run ./cmd/aman ingest secure-init -out data/ingest_keys.json
go run ./cmd/aman ingest http -addr :8080 -secure-keyring data/ingest_keys.json
go run ./cmd/aman ingest secure-pack -in events.json -out events.aman -keyring data/ingest_keys.json
curl -X POST "http://localhost:8080/ingest-secure?schema=native" --data-binary @events.aman
```

## Key Generation
```bash
go run ./cmd/aman ingest secure-keygen -out data/ingest_keys.json
```

## Pack
```bash
go run ./cmd/aman ingest secure-pack \
  -in events.json \
  -out events.aman \
  -keyring data/ingest_keys.json \
  -compress auto \
  -policy adaptive \
  -risk medium
```

## Unpack + Verify
```bash
go run ./cmd/aman ingest secure-unpack \
  -in events.aman \
  -out events.json \
  -keyring data/ingest_keys.json
```

## Key Rotation
```bash
go run ./cmd/aman ingest secure-rotate -in data/ingest_keys.json
```

## Health Checks
`/ingest-health` returns failure rates for HMAC verification, decrypt failures, and schema errors.

## Notes
- HMAC validation is mandatory; invalid envelopes are rejected.
- Compression is applied before encryption.
- Phase 2 will add hybrid key wrapping and signed metadata.
