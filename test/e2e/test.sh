#!/bin/sh
# Exercise the real Keycloak -> Snitch -> Warden -> Hookglass header-verification path.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
project=${E2E_PROJECT:-keycloak-warden-e2e}
compose_file="$root/test/e2e/compose.yaml"
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
    --admin-token development-admin-token \
    -o json
}

receiver_logs() {
  compose logs --no-log-prefix receiver 2>&1
}

wait_for_active_ban() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    bans=$(active_bans)
    if printf '%s' "$bans" | grep -Eq '"state"[[:space:]]*:[[:space:]]*"banned"' &&
      printf '%s' "$bans" | grep -Eq '"kind"[[:space:]]*:[[:space:]]*"automatic"'; then
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
      grep -Fq "\\\"state\\\":\\\"$desired\\\""; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  printf 'Webhook for state=%s was not observed\n' "$desired" >&2
  return 1
}

# Wait for Slack to acknowledge each revision before the next state change.
wait_for_slack() {
  [ "$slack_enabled" = enabled ] || return 0
  expected=$1
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if curl --silent --fail --max-time 3 "$warden_management/metrics" |
      grep -Fqx "warden_delivery_attempts_total{destination=\"webhook.slack-bot\",outcome=\"success\"} $expected"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  printf 'Slack did not acknowledge delivery %s; check the Warden delivery log.\n' "$expected" >&2
  return 1
}

slack_enabled=$(docker inspect --format '{{index .Config.Labels "warden.e2e.slack"}}' "$(compose ps -q warden)")
wait_http "$warden_management/readyz" "Warden"
wait_http "$receiver_url/healthz" "Hookglass"

# Confirm that Hookglass rejects requests without the configured header.
code=$(curl --silent --show-error --max-time 10 \
  --output /dev/null --write-out '%{http_code}' \
  -X POST --data '{"state":"banned"}' "$receiver_url/header")
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
ip=$(printf '%s' "$bans" | sed -n 's/.*"ipAddress"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -z "$ip" ]; then
  printf 'Could not find banned IP in Warden response: %s\n' "$bans" >&2
  exit 1
fi
printf 'Automatic ban: %s\n' "$ip"

wait_for_webhook banned
wait_for_slack 1
printf 'Verified header-authenticated banned-state webhook\n'

compose exec -T warden /keycloak-warden unban "$ip" \
  --admin-token development-admin-token \
  --output json

wait_for_webhook unbanned
wait_for_slack 2
if active_bans | grep -Eq '"state"[[:space:]]*:[[:space:]]*"banned"'; then
  printf 'Warden still reports an active ban after unban\n' >&2
  exit 1
fi
if ! curl --silent --fail "$warden_management/metrics" | grep -Fq 'warden_http_requests_total'; then
  printf 'Warden /metrics did not expose HTTP instrumentation\n' >&2
  exit 1
fi

# Warden records the Keycloak realm ID, not the display name. Keycloak assigns
# a fresh ID when importing this disposable realm, so discover it from the
# observed Snitch counter and require the decision counter to use the same ID.
metrics=$(curl --silent --show-error --fail "$warden_management/metrics")
realm_id=$(printf '%s\n' "$metrics" | sed -n 's/^warden_snitch_events_total{event_type="LOGIN_ERROR",realm="\([^"]*\)"} 2$/\1/p')
if [ -z "$realm_id" ] || [ "$realm_id" = unknown ]; then
  printf 'Missing realm-specific Snitch login failure counter (2 events)\n' >&2
  exit 1
fi
if ! printf '%s\n' "$metrics" | grep -Fqx "warden_automatic_ban_decisions_total{trigger_realm=\"$realm_id\"} 1"; then
  printf 'Missing automatic ban decision counter for realm ID %s\n' "$realm_id" >&2
  exit 1
fi
printf 'Verified realm-specific metrics for realm ID %s\n' "$realm_id"

success=true
printf '\nEnd-to-end OK: real failed logins -> signed Snitch events -> automatic ban -> header-authenticated webhook -> unban -> unbanned-state webhook.\n'
printf 'Inspect Hookglass logs: make e2e-logs\n'
