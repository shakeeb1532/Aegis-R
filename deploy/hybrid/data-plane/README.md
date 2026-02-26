# Data Plane (Customer Account)

## Purpose
Run Aman sidecar near the data. It pulls logs locally and only sends signed bundles and metadata to the control plane.

## Minimal Components
- Aman sidecar container
- Local state volume (state + audit log)
- IAM role with read access to customer logs
- Outbound HTTPS to control plane API

## Suggested Environment Variables
See `sidecar.env.example`.

## Data Flow
1. Pull logs from SIEM/EDR/IdP/Security Lake.
2. Run `assess` and `audit package`.
3. Push bundles to control plane endpoint.
