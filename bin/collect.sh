#!/usr/bin/env bash
# Pull measurement data from every node to the local collector directory.
#
# Reads a node list where each line is "<node_id> <ssh_target>":
#
#   host-a  admin@198.51.100.10
#   host-b  root@203.0.113.20
#   home    me@192.168.1.20
#
# Usage:
#   ./collect.sh nodes.txt ./data
#
# Intended to run from cron on the collector host (daily is plenty; the data
# is small). Pull-only - it never writes to the nodes.
set -euo pipefail

NODES_FILE="${1:?usage: collect.sh <nodes.txt> <dest-dir>}"
DEST="${2:?usage: collect.sh <nodes.txt> <dest-dir>}"
SSH_PORT="${SSH_PORT:-62222}"

[[ -f "$NODES_FILE" ]] || { echo "no such file: $NODES_FILE" >&2; exit 1; }

while read -r node target; do
    [[ -z "${node:-}" || "$node" == \#* ]] && continue
    echo "==> $node ($target)"
    mkdir -p "$DEST/$node"

    # /var/lib/honeypot -> snapshots/, ipdump/, manifest.txt
    rsync -az --info=stats1 -e "ssh -p $SSH_PORT -o BatchMode=yes" \
        "$target:/var/lib/honeypot/" "$DEST/$node/"

    # OpenCanary service log
    mkdir -p "$DEST/$node/opencanary"
    rsync -az --info=stats1 -e "ssh -p $SSH_PORT -o BatchMode=yes" \
        "$target:/var/log/opencanary/" "$DEST/$node/opencanary/"
done < "$NODES_FILE"

echo
echo "Collected into $DEST"
find "$DEST" -maxdepth 2 -type d | sort
