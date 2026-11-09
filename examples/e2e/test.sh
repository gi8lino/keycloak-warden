#!/bin/sh
# Exercise the real Keycloak -> Snitch -> Warden -> Hookglass header-verification path.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
project=${E2E_PROJECT:-keycloak-warden-e2e}
compose_file="$root/examples/e2e/compose.yaml"
keycloak_url="http://127.0.0.1:${E2E_KC_PORT:-18080}/realms/warden-e2e"
warden_management="http://127.0.0.1:${E2E_MANAGEMENT_PORT:-18082}"
receiver_url="http://127.0.0.1:${E2E_RECEIVER_PORT:-18090}"
token_url="$keycloak_url/protocol/openid-connect/token"
response_file=$(mktemp)
success=false

compose() {
  docker compose -p "$project" -f "$compose_file" "$@"
}

cleanup() {
  if [ "$success" != true ]; then
    printf '\n--- End-to-end service logs ---\n' >&2
    compose logs --tail 100 >&2 || true
  fi
  rm -f "$response_file"
}
trap cleanup EXIT HUP INT TERM

wait_http() {
  url=$1
  label=$2
  attempt=0
  while [ "$attempt" -lt 120 ]; do
    if curl --silent --show-error --fail --max-time 3 --output /dev/null "$url" 2>/dev/null; then
      printf 'Ready: %s\n' "$label"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  printf 'Timed out waiting for %s (%s)\n' "$label" "$url" >&2
  return 1
}

active_bans() {
  compose exec -T warden /keycloak-warden \
    list-active \
    --database /data/warden.db \
    --output json
}

receiver_logs() {
  compose logs --no-log-prefix receiver 2>&1
}

wait_for_active_ban() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    bans=$(active_bans)
    if printf '%s' "$bans" | grep -Fq '"active":true' &&
      printf '%s' "$bans" | grep -Fq '"failures":2'; then
      printf '%s\n' "$bans"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  printf 'No automatic ban after two real failed logins\n' >&2
  return 1
}

wait_for_webhook() {
  desired=$1
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if receiver_logs |
      grep -F 'event=webhook_received' |
      grep -F 'path=/header' |
      grep -F 'verified=true' |
      grep -Fq "\\\"active\\\":$desired"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  printf 'Webhook for active=%s was not observed\n' "$desired" >&2
  return 1
}

wait_http "$warden_management/readyz" "Warden"
wait_http "$receiver_url/healthz" "Hookglass"

# Confirm that Hookglass rejects requests without the configured header.
code=$(curl --silent --show-error --max-time 10 \
  --output /dev/null --write-out '%{http_code}' \
  -X POST --data '{"active":true}' "$receiver_url/header")
if [ "$code" != 401 ]; then
  printf 'Hookglass /header returned HTTP %s (expected 401)\n' "$code" >&2
  exit 1
fi

wait_http "$keycloak_url/.well-known/openid-configuration" "Keycloak"

for attempt in 1 2; do
  code=$(curl --silent --show-error --max-time 10 \
    --output "$response_file" \
    --write-out '%{http_code}' \
    --data-urlencode 'client_id=smoke' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'username=demo' \
    --data-urlencode 'password=wrong-password' \
    "$token_url")

  if [ "$code" != 400 ] || ! grep -Fq 'invalid_grant' "$response_file"; then
    printf 'Login attempt %s returned HTTP %s (expected invalid_grant)\n' "$attempt" "$code" >&2
    cat "$response_file" >&2
    exit 1
  fi
  printf 'Verified real failed login %s/2\n' "$attempt"
done

bans=$(wait_for_active_ban)
ip=$(printf '%s' "$bans" | sed -n 's/.*"ipAddress":"\([^"]*\)".*/\1/p')
if [ -z "$ip" ]; then
  printf 'Could not find banned IP in Warden response: %s\n' "$bans" >&2
  exit 1
fi
printf 'Automatic ban: %s\n' "$ip"

wait_for_webhook true
printf 'Verified header-authenticated active-ban webhook\n'

compose exec -T warden /keycloak-warden unban "$ip" \
  --admin-token development-admin-token \
  --output json

wait_for_webhook false
if active_bans | grep -Fq '"active":true'; then
  printf 'Warden still reports an active ban after unban\n' >&2
  exit 1
fi
if ! curl --silent --fail "$warden_management/metrics" | grep -Fq 'warden_http_requests_total'; then
  printf 'Warden /metrics did not expose HTTP instrumentation\n' >&2
  exit 1
fi

success=true
printf '\nEnd-to-end OK: real failed logins -> signed Snitch events -> automatic ban -> header-authenticated webhook -> unban -> release webhook.\n'
printf 'Inspect Hookglass logs: make e2e-logs\n'
