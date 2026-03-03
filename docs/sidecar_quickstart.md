# Aman Sidecar (Closed-Source) Quickstart

This is the **customer‑run** sidecar. It pulls Entra sign‑in logs inside their tenant and
sends **normalized events only** to your Aman ingest API. No source code is required.

## 1) You build and deliver the image (one‑time)

```bash
scripts/build_sidecar_image.sh
```

This produces a tarball:

```
out/aman-sidecar_pilot.tar
```

Deliver that file to the pilot customer securely.

## 2) Customer loads the image

```bash
docker load -i aman-sidecar_pilot.tar
```

## 3) Customer runs the sidecar

### Option A — one-liner

```bash
docker run --rm \
  -e ENTRA_TENANT_ID="..." \
  -e ENTRA_CLIENT_ID="..." \
  -e ENTRA_CLIENT_SECRET="..." \
  -e AMAN_INGEST_URL="https://your-aman-host:8080/v1/ingest?schema=native" \
  -e AMAN_INGEST_API_KEY="your-ingest-key" \
  -e WINDOW_MINUTES="15" \
  -e SLEEP_SECONDS="60" \
  aman-sidecar:pilot
```

### Option B — docker-compose (recommended for pilots)

Create a `.env` file in the same folder:

```env
ENTRA_TENANT_ID=...
ENTRA_CLIENT_ID=...
ENTRA_CLIENT_SECRET=...
AMAN_INGEST_URL=https://your-aman-host:8080/v1/ingest?schema=native
AMAN_INGEST_API_KEY=your-ingest-key
WINDOW_MINUTES=15
SLEEP_SECONDS=60
```

Run:

```bash
docker compose -f deploy/sidecar/docker-compose.yml up -d
```

The sidecar will:

1) Pull Graph sign‑ins (last window)
2) Normalize them to Aman atomic evidence
3) Post to your ingest API

## Notes

- Credentials are env vars only. Do **not** store secrets in files.
- The sidecar is **closed‑source**; only the binary is shipped.
- Output is stored inside the container under `/data/entra` (temporary).
