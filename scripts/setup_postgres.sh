#!/usr/bin/env bash
set -euo pipefail

# Setup PostgreSQL para Ubuntu, Debian e Fedora.
# Uso:
#   chmod +x scripts/setup_postgres.sh
#   ./scripts/setup_postgres.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_SQL="${SCRIPT_DIR}/init_database.sql"

if [[ ! -f "${INIT_SQL}" ]]; then
  echo "[ERRO] Arquivo init_database.sql não encontrado em ${INIT_SQL}" >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "[ERRO] Execute como root (sudo)." >&2
  exit 1
fi

install_postgres_debian_family() {
  echo "[INFO] Instalando PostgreSQL (Ubuntu/Debian)..."
  apt-get update -y
  apt-get install -y postgresql postgresql-contrib
  systemctl enable postgresql
  systemctl start postgresql
}

install_postgres_fedora() {
  echo "[INFO] Instalando PostgreSQL (Fedora)..."
  dnf install -y postgresql-server postgresql-contrib
  postgresql-setup --initdb || true
  systemctl enable postgresql
  systemctl start postgresql
}

if command -v apt-get >/dev/null 2>&1; then
  install_postgres_debian_family
elif command -v dnf >/dev/null 2>&1; then
  install_postgres_fedora
else
  echo "[ERRO] Distribuição não suportada por este script." >&2
  exit 1
fi

echo "[INFO] Aplicando script de inicialização da base..."
sudo -u postgres psql -v ON_ERROR_STOP=1 -f "${INIT_SQL}"

echo "[OK] PostgreSQL configurado com sucesso para o PhishGuard."
echo "[INFO] Database: phishguard"
echo "[INFO] User: phishguard_user"
echo "[INFO] Password: phishguard_password"
