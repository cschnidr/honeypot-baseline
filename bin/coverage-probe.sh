#!/usr/bin/env bash
# coverage-probe.sh -- prove that the entlure module LOGS what it serves.
#
# Lesson from window 1: "the service answers" is not "the service logs".
# The stock http module answered unknown paths with 404 and logged nothing,
# hiding path enumeration. Every lure here must therefore pass a probe that
# produces a log event, not just an HTTP response.
#
# Run from the admin machine against ONE node, after rollout:
#   bin/coverage-probe.sh <node-ip> <ssh-target> [scheme]
# Example (RFC-5737 address):
#   bin/coverage-probe.sh 203.0.113.7 "user@203.0.113.7 -p 62222" https
#
# It fires one unique-marker request at every lure path plus one unknown
# path, then greps the node's opencanary log for the marker and requires one
# hit per probe. Exit 0 = full logging coverage.
set -euo pipefail

TARGET="${1:?usage: coverage-probe.sh <node-ip> <ssh-target> [scheme=http|https]}"
SSH_TARGET="${2:?usage: coverage-probe.sh <node-ip> <ssh-target> [scheme=http|https]}"
SCHEME="${3:-https}"
PORT=443
[[ "$SCHEME" == "http" ]] && PORT=443  # entlure only; plain mode also listens here if TLS off
MARKER="covprobe-$(date +%s)-$$"
CURL_TLS=()
[[ "$SCHEME" == "https" ]] && CURL_TLS=(-k)  # self-referential probe: cert validity is le-setup's concern

PATHS=(
  "api/session/properties"
  "api/setup/validate"
  "owa/auth/logon.aspx"
  "ecp/"
  "autodiscover/autodiscover.xml"
  "_layouts/15/start.aspx"
  "_layouts/15/toolpane.aspx"
  "global-protect/login.esp"
)

SENT=0
for p in "${PATHS[@]}"; do
  curl -s "${CURL_TLS[@]}" -o /dev/null --max-time 10 \
    -A "$MARKER" "$SCHEME://$TARGET:$PORT/$p" || true
  SENT=$((SENT+1))
done
# one POST with a marker body (write-path logging) and one unknown path
curl -s "${CURL_TLS[@]}" -o /dev/null --max-time 10 \
  -A "$MARKER" -d "user=$MARKER&pw=$MARKER" \
  "$SCHEME://$TARGET:$PORT/owa/auth/logon.aspx" || true
SENT=$((SENT+1))
curl -s "${CURL_TLS[@]}" -o /dev/null --max-time 10 \
  -A "$MARKER" "$SCHEME://$TARGET:$PORT/no-such-path-$MARKER" || true
SENT=$((SENT+1))

sleep 2
# shellcheck disable=SC2086
HITS="$(ssh $SSH_TARGET "sudo grep -c '$MARKER' /var/log/opencanary/opencanary.log")"

echo "probes sent: $SENT, log events with marker: $HITS"
if [[ "$HITS" -eq "$SENT" ]]; then
  echo "COVERAGE OK - every probe produced a log event"
else
  echo "COVERAGE FAIL - $((SENT-HITS)) probe(s) produced no log event" >&2
  exit 1
fi
