#!/usr/bin/env bash
# Verify from OUTSIDE that every node exposes exactly the same ports.
# Without this check a per-port volume comparison is worthless.
#
#   ./verify-exposure.sh 3.120.0.1 5.9.0.2 46.101.0.3 84.75.0.4
#
# Run this from a host that is NOT inside ADMIN_CIDR - otherwise you also see
# the management port and the output differs for no real reason.
set -uo pipefail

PORTS=(21 22 23 25 80 110 139 143 443 445 587 1433 1521 2375 3306 3389 5432 5900 6379 8080 8443 9200 9418 11211 27017)
TIMEOUT=3

(( $# >= 2 )) || { echo "usage: $0 <ip> <ip> [ip ...]" >&2; exit 1; }

probe() {  # $1=host $2=port -> "open"|"closed"
    if timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
        echo open
    else
        echo closed
    fi
}

declare -A RESULT
printf '%-8s' "PORT"
for host in "$@"; do printf '%-18s' "$host"; done
echo

for port in "${PORTS[@]}"; do
    printf '%-8s' "$port"
    for host in "$@"; do
        state="$(probe "$host" "$port")"
        RESULT["$host:$port"]="$state"
        printf '%-18s' "$state"
    done
    echo
done

echo
FAIL=0
REF="$1"
for port in "${PORTS[@]}"; do
    for host in "${@:2}"; do
        if [[ "${RESULT["$host:$port"]}" != "${RESULT["$REF:$port"]}" ]]; then
            echo "MISMATCH port $port: $REF=${RESULT["$REF:$port"]} $host=${RESULT["$host:$port"]}"
            FAIL=1
        fi
    done
done

if (( FAIL )); then
    echo
    echo "-> Nodes are NOT comparable. Fix this before starting the measurement window."
    exit 1
fi
echo "OK - all nodes expose identical ports."
