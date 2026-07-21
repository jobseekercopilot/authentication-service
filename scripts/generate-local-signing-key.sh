#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"
env_file="${project_dir}/.env"

if [[ -e "${env_file}" ]]; then
  echo "Refusing to overwrite the existing ignored .env file." >&2
  echo "Move it aside explicitly before rotating the local signing key." >&2
  exit 1
fi

umask 077
signing_key="$(openssl rand -base64 48)"
database_password="$(openssl rand -hex 24)"
printf 'JWT_SIGNING_KEY=%s\nAUTH_DB_PASSWORD=%s\n' \
  "${signing_key}" "${database_password}" > "${env_file}"
unset signing_key database_password

echo "Created an ignored, owner-readable .env file. Secrets were not displayed."
echo "Replacing this file later invalidates existing local JWTs and requires a new login."
