#!/usr/bin/env bash
# Live honeypot dashboard: volume (nftables) + content (OpenCanary), on one node.
#
#   sudo hp-watch.sh [refresh_seconds]   # default 5
#
# Read-only. Ctrl-C to quit. Intended to be run ON a honeypot node, not the
# collector. For cross-node comparison use bin/analyze.py instead.
set -uo pipefail

INTERVAL="${1:-5}"
TABLE="inet hp"
LOG=/var/log/opencanary/opencanary.log

command -v nft >/dev/null || { echo "nft not found - run this on a honeypot node" >&2; exit 1; }
command -v jq  >/dev/null || { echo "jq not found" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run as root (sudo hp-watch.sh)" >&2; exit 1; }

while true; do
  clear
  node="$(cat /etc/honeypot-node-id 2>/dev/null || echo '?')"
  echo "honeypot [$node]  $(date -u +%FT%TZ)   refresh ${INTERVAL}s, Ctrl-C to quit"
  echo "=================================================================="

  tbl="$(nft -j list table $TABLE 2>/dev/null)"
  syn=$(jq '[.nftables[].counter | select(.name|startswith("c_t")) | .packets] | add // 0' <<<"$tbl")
  udp=$(jq '[.nftables[].counter | select(.name|startswith("c_u")) | .packets] | add // 0' <<<"$tbl")
  oth=$(jq '[.nftables[].counter | select(.name=="c_tcp_other") | .packets] | add // 0' <<<"$tbl")
  v4=$(nft -j list set $TABLE scan4 2>/dev/null | jq '[.nftables[].set.elem // [] | length] | add // 0')
  v6=$(nft -j list set $TABLE scan6 2>/dev/null | jq '[.nftables[].set.elem // [] | length] | add // 0')

  printf "SYN(TCP): %-10s  UDP pkts: %-10s  tcp_other: %-10s\n" "$syn" "$udp" "$oth"
  printf "unique sources -> v4: %-8s  v6: %s\n\n" "$v4" "$v6"

  echo "-- top TCP ports by SYN --"
  jq -r '.nftables[].counter
         | select(.name|startswith("c_t")) | select(.packets>0)
         | "\(.packets) \(.name|ltrimstr("c_t"))"' <<<"$tbl" \
    | sort -rn | head -8 | awk '{printf "  port %-8s %s SYN\n",$2,$1}'

  echo
  if [[ -r "$LOG" ]]; then
    echo "-- OpenCanary: $(wc -l < "$LOG") events --"
    echo "  top credentials (user:pass):"
    jq -r 'select(.logdata.USERNAME!=null or .logdata.PASSWORD!=null)
           | "\(.logdata.USERNAME // "-"):\(.logdata.PASSWORD // "-")"' "$LOG" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
    echo "  top HTTP paths:"
    jq -r 'select(.logdata.PATH!=null) | .logdata.PATH' "$LOG" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
    echo "  most recent:"
    tail -n 3 "$LOG" 2>/dev/null \
      | jq -rc '"\(.local_time // .local_time_adjusted)  \(.src_host)  logtype=\(.logtype)"' 2>/dev/null \
      | sed 's/^/    /'
  else
    echo "-- OpenCanary log not readable (need root / no events yet) --"
  fi

  sleep "$INTERVAL"
done
