#!/bin/bash
# Instalación en una línea:
#   curl -fsSL https://raw.githubusercontent.com/Vilchaco/pingmon/main/install.sh | bash -s -- <host[:puerto] del servidor RTMP>
# Volver a ejecutarla actualiza el código y conserva la configuración.
set -euo pipefail

main() {
  local repo="Vilchaco/pingmon" branch="main"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  echo "Descargando pingmon ($repo@$branch)..."
  curl -fsSL "https://github.com/$repo/archive/refs/heads/$branch.tar.gz" | tar -xz -C "$TMP_DIR"
  bash "$TMP_DIR/pingmon-$branch/instalar.command" "$@"
}

main "$@"
