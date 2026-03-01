#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/aman"
OUT_DIR="${ROOT_DIR}/data/local"
KEY_DIR="${OUT_DIR}/keys"
USERS_FILE="${OUT_DIR}/users.json"

if [[ ! -x "${BIN}" ]]; then
  echo "Binary not found: ${BIN}" >&2
  echo "Build it first: go build -o aman ./cmd/aman" >&2
  exit 1
fi

mkdir -p "${KEY_DIR}"

echo "Generating local keypairs..."
"${BIN}" keys -out "${KEY_DIR}/requester_keypair.json"
"${BIN}" keys -out "${KEY_DIR}/approver_keypair.json"
"${BIN}" keys -out "${KEY_DIR}/admin_keypair.json"

cat > "${USERS_FILE}" <<EOF
[
  {
    "id": "requester-1",
    "name": "Requester",
    "role": "requester",
    "keypair": "data/local/keys/requester_keypair.json"
  },
  {
    "id": "approver-1",
    "name": "Approver",
    "role": "approver",
    "keypair": "data/local/keys/approver_keypair.json"
  },
  {
    "id": "admin-1",
    "name": "Admin",
    "role": "admin",
    "keypair": "data/local/keys/admin_keypair.json"
  }
]
EOF

echo "Local users written: ${USERS_FILE}"
echo "Keypairs stored in: ${KEY_DIR}"
