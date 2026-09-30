#!/usr/bin/env bash
# Verify from OUTSIDE that every node exposes exactly the same ports.
# Without this check a per-port volume comparison is worthless.
#
#   ./verify-exposure.sh 3.120.0.1 5.9.0.2 46.101.0.3 84.75.0.4
#
# Run from a host that is NOT inside ADMIN_CIDR - otherwise you also see the
# management port and the output differs for no real reason.
#
# Deliberately portable: pure-bash /dev/tcp probing with a background-process
# watchdog for the timeout. No `declare -A` and no GNU `timeout`, so it runs on
# a stock macOS bash 3.2 as well as on Linux. On any mismatch it prints the
# offending ports and exits non-zero - it never silently reports "OK".
set -uo pipefail

PORTS=(21 22 23 25 80 110 139 143 443 445 587 1433 1521 2375 3306 3389 5432 5900 6379 8080 8443 9200 9418 11211 27017)
TIMEOUT="${TIMEOUT:-3}"

[ "$#" -ge 2 ] || { echo "usage: $0 <ip> <ip> [ip ...]" >&2; exit 1; }

# probe HOST PORT -> sets global STATE to "open" or "closed".
# A filtered port (silent drop, chain policy is `drop`) would hang a bare
# /dev/tcp connect forever, so a watchdog subshell kills it after $TIMEOUT.
STATE=""
probe() {
    local host=$1 port=$2 pid watcher
    ( exec 3<>"/dev/tcp/$host/$port" ) >/dev/null 2>&1 &
    pid=$!
    ( sleep "$TIMEOUT"; kill -9 "$pid" ) >/dev/null 2>&1 &
    watcher=$!
    if wait "$pid" 2>/dev/null; then STATE=open; else STATE=closed; fi
    kill -9 "$watcher" >/dev/null 2>&1 || true
    wait "$watcher" 2>/dev/null || true
}

# Header
printf '%-8s' "PORT"
for host in "$@"; do printf '%-18s' "$host"; done
echo

FAIL=0
MISMATCHES=""
ref_host="$1"
for port in "${PORTS[@]}"; do
    printf '%-8s' "$port"
    ref_state=""
    idx=0
    for host in "$@"; do
        probe "$host" "$port"
        printf '%-18s' "$STATE"
        if [ "$idx" -eq 0 ]; then
            ref_state="$STATE"
        elif [ "$STATE" != "$ref_state" ]; then
            MISMATCHES="${MISMATCHES}
  MISMATCH port $port: ${ref_host}=${ref_state} ${host}=${STATE}"
            FAIL=1
        fi
        idx=$((idx + 1))
    done
    echo
done

echo
if [ "$FAIL" -ne 0 ]; then
    printf '%s\n' "$MISMATCHES"
    echo
    echo "-> Nodes are NOT comparable. Fix this before starting the measurement window."
    exit 1
fi
echo "OK - all nodes expose identical ports."
