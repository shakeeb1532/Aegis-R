# Aman UI

UI for **Aman** by **Amanah Forensics**.

This UI is pilot-focused for audit and governance workflows:
- Command Center (decision and integrity status)
- Decision views (why-chain, evidence gaps)
- Governance (approval status, dual-control visibility)
- Audit bundle download/verify flows

## Local Dev
```bash
cd /Users/shak1532/Downloads/Aegis-R/ui
npm install
npm run dev
```

## Build
```bash
cd /Users/shak1532/Downloads/Aegis-R/ui
npm run build
```

## Connect to Local API
Run backend API first:

```bash
cd /Users/shak1532/Downloads/Aegis-R
go run ./cmd/aman serve-api \
  -addr :8081 \
  -report data/report.json \
  -audit data/audit.log \
  -approvals data/approvals.log
```

Run UI against API:

```bash
cd /Users/shak1532/Downloads/Aegis-R/ui
VITE_API_BASE=http://localhost:8081 npm run dev
```

## Verification
```bash
cd /Users/shak1532/Downloads/Aegis-R/ui
npm run build
```

Expected:
- TypeScript compile passes
- Vite production bundle is generated in `ui/dist`

## Notes
- If API is unavailable, the UI falls back to sample data for visual testing.
- For pilot demos, use real API mode (`VITE_API_BASE`) to show live governance/audit status.
- Backend enforces conditional trust boundaries (`requires`) and stricter credential-access signals; keep `env.json` and `rules.json` aligned.
