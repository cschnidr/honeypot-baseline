#!/usr/bin/env python3
"""Build one JSONL line from a node's nftables snapshots.

Usage:
    hp_snapshot.py <node_id> <ts> <counters.json> <scan4.json> <scan6.json>

Prints exactly one JSON object on stdout; the caller appends it to the
node's daily file.
"""
import json
import sys


def load(path):
    with open(path) as fh:
        return json.load(fh)["nftables"]


def counters(path):
    """Map counter name -> {packets, bytes}."""
    out = {}
    for obj in load(path):
        c = obj.get("counter")
        if c:
            out[c["name"]] = {"packets": c["packets"], "bytes": c["bytes"]}
    return out


def setsize(path):
    """Number of elements in the dynamic set (= unique source IPs)."""
    total = 0
    for obj in load(path):
        s = obj.get("set")
        if s:
            total += len(s.get("elem", []))
    return total


def main(argv):
    if len(argv) != 6:
        print(__doc__, file=sys.stderr)
        return 2
    node_id, ts, counters_json, scan4_json, scan6_json = argv[1:]
    print(json.dumps({
        "node": node_id,
        "ts": ts,
        "unique_src_v4": setsize(scan4_json),
        "unique_src_v6": setsize(scan6_json),
        "counters": counters(counters_json),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
