# Inventory Ingestion Schema (File-Based)

Aegis-R can build `env.json` from provider inventory exports. Place files under `data/inventory/`:

- `aws.json`
- `okta.json`
- `azure.json`
- `gcp.json`

Then run:

```bash
go run ./cmd/aegisr ingest-inventory -in data/inventory -out data/env.json
```

To detect drift versus an existing `env.json`:

```bash
go run ./cmd/aegisr inventory-drift -base data/env.json -in data/inventory -out drift.json
```

## AWS (`aws.json`)
```json
{
  "accounts": [{"id": "111111111111", "name": "prod", "tags": ["tier:prod"]}],
  "users": [{"id": "aws-user-1", "username": "alice", "priv_level": "admin", "tags": ["team:soc"]}],
  "roles": [{"id": "role-app", "name": "app-role", "priv_level": "elevated", "trusts": ["aws-user-1"], "tags": ["service:app"]}],
  "instances": [{"id": "i-01", "name": "web-01", "vpc": "vpc-1", "subnet": "subnet-1", "zone": "us-east-1a", "critical": true, "tags": ["env:prod"]}],
  "security_groups": [{"id": "sg-01", "name": "web-sg", "vpc": "vpc-1", "ingress": [{"source": "0.0.0.0/0", "destination": "sg-01", "protocol": "tcp", "port": "443", "notes": "public https"}], "egress": []}],
  "vpcs": [{"id": "vpc-1", "name": "prod-vpc", "tags": []}],
  "subnets": [{"id": "subnet-1", "vpc": "vpc-1", "zone": "us-east-1a", "tags": []}]
}
```

## Okta (`okta.json`)
```json
{
  "users": [{"id": "okta-user-1", "email": "analyst@example.com", "role": "analyst", "priv_level": "standard", "groups": ["SOC"], "status": "ACTIVE"}],
  "groups": [{"id": "grp-soc", "name": "SOC", "tags": ["team:soc"], "users": ["okta-user-1"]}],
  "roles": [{"id": "role-approver", "name": "Approver", "users": ["okta-user-1"]}],
  "apps": [{"id": "app-1", "name": "Aegis-R", "users": ["okta-user-1"], "tags": ["critical"]}]
}
```

## Azure / Entra (`azure.json`)
```json
{
  "users": [{"id": "azure-user-1", "upn": "bob@contoso.com", "priv_level": "standard", "groups": ["SecOps"]}],
  "groups": [{"id": "grp-secops", "name": "SecOps", "tags": ["team:soc"], "users": ["azure-user-1"]}],
  "role_assignments": [{"principal": "azure-user-1", "role": "Reader", "scope": "subscription:sub-01"}],
  "networks": [{"id": "vnet-01", "name": "core-vnet", "tags": ["region:eastus"]}],
  "subnets": [{"id": "subnet-az-1", "network": "vnet-01", "zone": "eastus-1", "tags": ["tier:app"]}],
  "nsgs": [{"id": "nsg-01", "name": "core-nsg", "network": "vnet-01", "rules": [{"source": "10.0.0.0/24", "destination": "subnet-az-1", "protocol": "tcp", "port": "3389", "action": "allow", "notes": "admin rdp"}]}]
}
```

## GCP (`gcp.json`)
```json
{
  "projects": [{"id": "proj-01", "name": "prod", "tags": ["tier:prod"]}],
  "users": [{"id": "gcp-user-1", "email": "carol@example.com", "priv_level": "standard", "groups": ["SOC"]}],
  "service_accounts": [{"id": "sa-01", "email": "svc@app.iam.gserviceaccount.com", "priv_level": "elevated", "tags": ["service:app"]}],
  "iam_bindings": [{"member": "sa-01", "role": "roles/compute.admin", "scope": "project:proj-01"}],
  "networks": [{"id": "net-01", "name": "core", "tags": ["region:us-central1"]}],
  "subnets": [{"id": "subnet-gcp-1", "network": "net-01", "zone": "us-central1-a", "tags": ["tier:app"]}],
  "firewall_rules": [{"id": "fw-01", "network": "net-01", "direction": "INGRESS", "source": "0.0.0.0/0", "destination": "subnet-gcp-1", "protocol": "tcp", "port": "22", "action": "allow", "notes": "ssh"}]
}
```

Notes
- The ingestion layer is deterministic and file-based.
- AWS adapter now supports live API ingestion using the default AWS credential chain (env vars, shared config, instance profile), optional profile, and optional assume-role.
- Okta adapter supports live API ingestion using org URL + token (group/user/app data with best-effort permissions).
- Azure adapter supports live API ingestion using tenant/client credentials + subscription.
- GCP adapter is stubbed until credentials are wired in.
