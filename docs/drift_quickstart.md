# Drift Quickstart

This creates a minimal auto-drift workflow (baseline + scheduled refresh) for Aman.

## 1) Generate the quickstart assets
```bash
aman system drift-quickstart --outdir data/inventory
```

This writes:
- `data/inventory/auto_drift.sh`
- `data/inventory/auto_drift_README.md`

## 2) Create the initial baseline
```bash
aman inventory-refresh -provider all \
  -config data/inventory/config.json \
  -base data/env.json \
  -out data/env.json \
  -drift data/drift.json \
  -drift-request data/drift_request.json
```

## 3) Start continuous drift monitoring
```bash
bash data/inventory/auto_drift.sh
```

This will:
- refresh inventory on a schedule
- update `data/env.json`
- write a drift report (`data/drift.json`)
- emit a drift approval request when changes are detected

## Systemd example (optional)
```ini
[Unit]
Description=Aman inventory auto drift

[Service]
ExecStart=/bin/bash /path/to/data/inventory/auto_drift.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Notes
- Keep `data/inventory/config.json` updated with API credentials.
- Use `inventory-schedule` directly if you want custom intervals.
