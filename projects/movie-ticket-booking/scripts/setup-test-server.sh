#!/usr/bin/env bash
# setup-test-server.sh
# Automates Go + Docker setup on a fresh Ubuntu 24.04 server so that
#   go test -v -timeout 300s ./tests/integration/
# passes out of the box.
#
# Usage (run AS root or with sudo privileges):
#   chmod +x setup-test-server.sh
#   ./setup-test-server.sh
#
# Non-interactive: every apt/snap/curl step is idempotent — safe to re-run.

set -euo pipefail

GO_VERSION="1.24.3"
GO_ARCH="amd64"   # change to arm64 on ARM servers
GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
GO_INSTALL_DIR="/usr/local"
GO_BIN="${GO_INSTALL_DIR}/go/bin/go"

log() { echo "[setup] $*"; }

# ── 1. System packages ────────────────────────────────────────────────────────
log "Updating package index..."
sudo apt-get update -qq

log "Installing dependencies (curl, rsync, git, ca-certificates)..."
sudo apt-get install -y -qq curl rsync git ca-certificates

# ── 2. Docker (official repo) ─────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    sudo apt-get install -y -qq apt-transport-https gnupg lsb-release
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo \
        "deb [arch=${GO_ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io
    sudo systemctl enable --now docker
else
    log "Docker already installed: $(docker --version)"
fi

# Add current user to docker group so tests don't need sudo
if ! groups | grep -q docker; then
    log "Adding $(whoami) to docker group (re-login required for group to take effect)..."
    sudo usermod -aG docker "$(whoami)"
fi

# ── 3. Go ─────────────────────────────────────────────────────────────────────
if [[ -x "${GO_BIN}" ]]; then
    INSTALLED_VER="$("${GO_BIN}" version | awk '{print $3}')"
    log "Go already installed: ${INSTALLED_VER}"
else
    log "Downloading Go ${GO_VERSION}..."
    curl -sL "${GO_URL}" -o "/tmp/${GO_TARBALL}"
    log "Installing Go to ${GO_INSTALL_DIR}..."
    sudo rm -rf "${GO_INSTALL_DIR}/go"
    sudo tar -C "${GO_INSTALL_DIR}" -xzf "/tmp/${GO_TARBALL}"
    rm "/tmp/${GO_TARBALL}"
    log "Go installed: $("${GO_BIN}" version)"
fi

# Persist Go in PATH for current and future shells
PROFILE_LINE="export PATH=\$PATH:${GO_INSTALL_DIR}/go/bin"
if ! grep -qF "${GO_INSTALL_DIR}/go/bin" ~/.bashrc; then
    echo "${PROFILE_LINE}" >> ~/.bashrc
    log "Added Go to ~/.bashrc"
fi
export PATH="$PATH:${GO_INSTALL_DIR}/go/bin"

# ── 4. Pre-pull Docker images (optional but speeds up first test run) ─────────
log "Pre-pulling testcontainer images..."
docker pull redis:7-alpine  || true
docker pull mongo:7         || true

# ── 5. Smoke test ─────────────────────────────────────────────────────────────
log "Go version : $(go version)"
log "Docker     : $(docker --version)"
log "Docker daemon: $(sudo systemctl is-active docker)"

log ""
log "✅  Setup complete."
log ""
log "Next steps:"
log "  1. Copy the backend source to this server:"
log "     rsync -az --exclude='.git' ./backend/ user@<this-server>:~/mtb-backend/"
log "  2. SSH in and run:"
log "     cd ~/mtb-backend"
log "     go mod download"
log "     go test -v -timeout 300s ./tests/integration/"
log ""
log "NOTE: If you just added yourself to the docker group, log out and back in"
log "      before running the tests (or prefix with: newgrp docker)."
