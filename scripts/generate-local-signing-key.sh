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
key_dir="$(mktemp -d)"
trap 'rm -rf "${key_dir}"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${key_dir}/private.pem" 2>/dev/null
openssl pkey -in "${key_dir}/private.pem" -outform DER -out "${key_dir}/private.der"
openssl pkey -in "${key_dir}/private.pem" -pubout -outform DER -out "${key_dir}/public.der"
private_key="$(base64 -w0 < "${key_dir}/private.der")"
public_key="$(base64 -w0 < "${key_dir}/public.der")"
database_password="$(openssl rand -hex 24)"
printf 'JWT_PRIVATE_KEY_BASE64=%s\nJWT_PUBLIC_KEY_BASE64=%s\nAUTH_DB_PASSWORD=%s\n' \
  "${private_key}" "${public_key}" "${database_password}" > "${env_file}"
unset private_key public_key database_password

echo "Created an ignored, owner-readable .env file. Secrets were not displayed."
echo "Replacing this file later requires a new JWT_KEY_ID and deliberate overlap or re-login."
