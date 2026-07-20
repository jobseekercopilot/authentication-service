#!/usr/bin/env bash
set -euo pipefail

base_url="${AUTH_BASE_URL:-http://localhost:8084}"
email="auth-smoke-$(date +%s)-${RANDOM}@example.test"
password='Local-smoke-only-2026!'

register_payload="$(printf '{"name":"Auth Smoke","email":"%s","password":"%s"}' "${email}" "${password}")"
printf '%s' "${register_payload}" | curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  --output /dev/null \
  "${base_url}/api/auth/register"

login_payload="$(printf '{"email":"%s","password":"%s"}' "${email}" "${password}")"
token="$(printf '%s' "${login_payload}" | curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  "${base_url}/api/auth/login" | jq --exit-status --raw-output '.token | select(type == "string" and length > 0)')"

curl --fail --silent --show-error \
  --header "Authorization: Bearer ${token}" \
  --output /dev/null \
  "${base_url}/api/auth/me"

unset token password register_payload login_payload
echo "Authentication registration, login and authenticated lookup passed."
