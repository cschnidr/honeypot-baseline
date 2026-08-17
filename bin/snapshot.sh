#!/usr/bin/env bash
# Write a counter snapshot as one JSONL line.
#   hp-snapshot            -> counters + number of unique source IPs (hourly)
#   hp-snapshot --ipdump   -> additionally the full IP list (daily)
set -euo pipefail

DATA=/var/lib/honeypot
HELPER=${HELPER:-/usr/local/lib/hp_snapshot.py}
NODE_ID="$(cat /etc/honeypot-node-id)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
DAY="$(date -u +%F)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$DATA/snapshots" "$DATA/ipdump"

nft -j list counters table inet hp > "$TMP/counters.json"
nft -j list set inet hp scan4      > "$TMP/scan4.json"
nft -j list set inet hp scan6      > "$TMP/scan6.json"

python3 "$HELPER" "$NODE_ID" "$TS" \
    "$TMP/counters.json" "$TMP/scan4.json" "$TMP/scan6.json" \
    >> "$DATA/snapshots/${NODE_ID}-${DAY}.jsonl"

if [[ "${1:-}" == "--ipdump" ]]; then
    gzip -c "$TMP/scan4.json" > "$DATA/ipdump/${NODE_ID}-${DAY}-v4.json.gz"
    gzip -c "$TMP/scan6.json" > "$DATA/ipdump/${NODE_ID}-${DAY}-v6.json.gz"
fi
