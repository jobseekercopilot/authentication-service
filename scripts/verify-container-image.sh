#!/usr/bin/env sh
set -eu

image=${1:-authentication-service:local}

fail() {
    echo "container policy: $1" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"

metadata=$(docker image inspect "$image") || fail "image is missing: $image"

printf '%s' "$metadata" | jq -e '
    length == 1 and
    .[0].Config.User == "10001:10001" and
    .[0].Config.Healthcheck.Test[0] == "CMD-SHELL" and
    (.[0].Config.Healthcheck.Test[1] | contains("/actuator/health")) and
    .[0].Config.StopSignal == "SIGTERM" and
    .[0].Config.ExposedPorts["8084/tcp"] == {} and
    .[0].Config.Labels["org.opencontainers.image.licenses"] == "LicenseRef-Proprietary"
' >/dev/null || fail "image metadata does not meet the runtime policy"

history=$(docker history --no-trunc --format '{{.CreatedBy}}' "$image") \
    || fail "image history could not be read"
printf '%s' "$history" | grep -Eq 'JWT_PRIVATE_KEY_BASE64|JWT_PUBLIC_KEY_BASE64|AUTH_DB_PASSWORD|AUTH_SERVICE_TOKEN|AUTH_ENVIRONMENT_DATA_TOKEN' \
    && fail "image history contains a secret variable name"

echo "container policy: non-root identity, health check, SIGTERM, port, licence and history checks passed"
