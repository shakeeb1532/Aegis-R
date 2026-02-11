# Aegis-R UI

Standalone SaaS console for Aegis-R.

## Local Dev
```bash
npm install
npm run dev
```

## API (Demo)
Run the file-backed API server:
```bash
go run ./cmd/aegisr serve-api \
  -addr :8081 \
  -report data/report.json \
  -audit data/audit.log \
  -approvals data/approvals.log
```

Point the UI at the API:
```bash
VITE_API_BASE=http://localhost:8081 npm run dev
```

## Build
```bash
npm run build
```

The UI falls back to static sample data if the API is unavailable.
