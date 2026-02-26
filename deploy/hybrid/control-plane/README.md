# Control Plane (Amanah Forensics)

## Purpose
Host the UI and control API while storing evidence bundles and metadata.

## Minimal Components
- UI (Next.js/React)
- Control API (Go or Next API routes)
- Auth/SSO (Cognito/Clerk)
- Metadata DB (Postgres)
- Evidence store (S3)

## Suggested Environment Variables
See `control-plane.env.example`.

## Data Flow
1. Customer sidecar pushes signed bundle + metadata.
2. Control API stores bundle in S3 and metadata in Postgres.
3. UI reads metadata and downloads bundles via pre-signed URLs.

## Next Step
Create infra in AWS using ECS/Fargate + RDS + S3 + ALB.
