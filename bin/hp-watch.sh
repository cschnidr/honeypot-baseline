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

# OpenCanary logtype -> human name (from opencanary/logger.py). Single source of
# truth, used for both the event-type breakdown and the "most recent" line.
LTMAP='{"1000":"boot","1001":"msg","1002":"debug","1003":"error","1004":"ping","2000":"FTP login","2001":"FTP auth-init","3000":"HTTP GET","3001":"HTTP POST-login","3002":"HTTP bad-method","3003":"HTTP redirect","4000":"SSH connect","4001":"SSH version","4002":"SSH login","5001":"port SYN","6001":"Telnet login","6002":"Telnet connect","7001":"HTTPproxy login","8001":"MySQL login","9001":"MSSQL login","9002":"MSSQL winauth","9003":"MySQL connect","12001":"VNC","14001":"RDP","16001":"Git clone","17001":"Redis cmd","20001":"MongoDB login"}'

command -v nft >/dev/null || { echo "nft not found - run this on a honeypot node" >&2; exit 1; }
command -v jq  >/dev/null || { echo "jq not found" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run as root (sudo hp-watch.sh)" >&2; exit 1; }

while true; do
  clear
  node="$(cat /etc/honeypot-node-id 2>/dev/null || echo '?')"
  echo "honeypot [$node]  $(date -u +%FT%TZ)   refresh ${INTERVAL}s, Ctrl-C to quit"
  echo "=================================================================="

  tbl="$(nft -j list table $TABLE 2>/dev/null)"
  syn=$(jq '[.nftables[] | .counter // empty | select(.name|startswith("c_t")) | .packets] | add // 0' <<<"$tbl")
  udp=$(jq '[.nftables[] | .counter // empty | select(.name|startswith("c_u")) | .packets] | add // 0' <<<"$tbl")
  oth=$(jq '[.nftables[] | .counter // empty | select(.name=="c_tcp_other") | .packets] | add // 0' <<<"$tbl")
  v4=$(nft -j list set $TABLE scan4 2>/dev/null | jq '[.nftables[].set.elem // [] | length] | add // 0')
  v6=$(nft -j list set $TABLE scan6 2>/dev/null | jq '[.nftables[].set.elem // [] | length] | add // 0')

  printf "SYN(TCP): %-10s  UDP pkts: %-10s  tcp_other: %-10s\n" "$syn" "$udp" "$oth"
  printf "unique sources -> v4: %-8s  v6: %s\n\n" "$v4" "$v6"

  echo "-- top TCP ports by SYN --"
  jq -r '.nftables[] | .counter // empty
         | select(.name|test("^c_t[0-9]+$")) | select(.packets>0)
         | "\(.packets) \(.name|ltrimstr("c_t"))"' <<<"$tbl" \
    | sort -rn | head -8 | awk '{printf "  port %-8s %s SYN\n",$2,$1}'

  echo
  if [[ -r "$LOG" ]]; then
    echo "-- OpenCanary: $(wc -l < "$LOG") events --"
    echo "  event types:"
    jq -r '.logtype' "$LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -8 \
      | jq -R --argjson m "$LTMAP" -r 'split(" ") | map(select(length>0))
             | "    \(.[0])  \($m[.[1]] // ("logtype "+.[1]))  (\(.[1]))"' 2>/dev/null
    echo "  top credentials (user:pass):"
    jq -r 'select(.logdata.USERNAME!=null or .logdata.PASSWORD!=null)
           | "\(.logdata.USERNAME // "-"):\(.logdata.PASSWORD // "-")"' "$LOG" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
    echo "  top HTTP paths:"
    jq -r 'select(.logdata.PATH!=null) | .logdata.PATH' "$LOG" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
    echo "  most recent:"
    tail -n 3 "$LOG" 2>/dev/null \
      | jq -rc --argjson m "$LTMAP" '"    \(.local_time // .local_time_adjusted)  \(.src_host)  \($m[(.logtype|tostring)] // ("logtype "+(.logtype|tostring)))"' 2>/dev/null
  else
    echo "-- OpenCanary log not readable (need root / no events yet) --"
  fi

  sleep "$INTERVAL"
done
