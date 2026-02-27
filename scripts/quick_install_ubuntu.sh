#!/usr/bin/env bash
set -euo pipefail

GO_VERSION=${GO_VERSION:-1.24.0}
REPO_URL=${REPO_URL:-"https://github.com/shakeeb1532/Aegis-R.git"}
INSTALL_DIR=${INSTALL_DIR:-"$HOME/aman"}

log() { printf "[aman-install] %s\n" "$*"; }

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required" >&2
  exit 1
fi

log "Updating packages"
sudo apt-get update -y
sudo apt-get install -y curl git ca-certificates build-essential

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) GO_ARCH=amd64 ;;
  aarch64|arm64) GO_ARCH=arm64 ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
 esac

need_go=true
if command -v go >/dev/null 2>&1; then
  GOV=$(go env GOVERSION | sed 's/go//')
  if [[ "$GOV" == "$GO_VERSION" ]]; then
    need_go=false
  fi
fi

if $need_go; then
  log "Installing Go $GO_VERSION"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  rm -f /tmp/go.tgz
  if ! grep -q '/usr/local/go/bin' "$HOME/.profile"; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.profile"
  fi
  export PATH=$PATH:/usr/local/go/bin
fi

log "Cloning repo to $INSTALL_DIR"
if [ -d "$INSTALL_DIR" ]; then
  log "Directory exists, pulling latest"
  git -C "$INSTALL_DIR" pull --ff-only
else
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
log "Building aman"
go build -o aman ./cmd/aman

log "Done. Try: ./aman --help"
