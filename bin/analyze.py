#!/usr/bin/env python3
"""Aggregate the collected honeypot data into comparable per-node numbers.

Input is the collector directory produced by bin/collect.sh:

    data/<node>/snapshots/<node>-<YYYY-MM-DD>.jsonl
    data/<node>/ipdump/<node>-<YYYY-MM-DD>-v4.json.gz
    data/<node>/opencanary/opencanary.log
    data/<node>/manifest.txt

Usage:
    analyze.py data/ --start 2026-08-19T00:00:00Z --end 2026-09-09T00:00:00Z
    analyze.py data/ --csv out.csv

--start/--end bound the measurement window; use them to exclude the 48h
burn-in. Counters are monotonic, so volumes are computed as deltas between
consecutive snapshots and summed inside the window. A counter that goes
backwards (node reboot, ruleset reload) is treated as a reset and its new
value counted from zero.

Standard library only - no third-party dependencies.
"""
import argparse
import collections
import csv
import gzip
import json
import pathlib
import sys
from datetime import datetime, timezone

TS_FMT = "%Y%m%dT%H%M%SZ"


def parse_ts(value):
    """Accept both snapshot format (20260816T210000Z) and ISO-8601."""
    try:
        return datetime.strptime(value, TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_snapshots(node_dir):
    """Yield snapshot dicts sorted by timestamp."""
    rows = []
    for path in sorted((node_dir / "snapshots").glob("*.jsonl")):
        with path.open() as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    row["_ts"] = parse_ts(row["ts"])
                    rows.append(row)
                except (ValueError, KeyError) as exc:
                    print(f"  warn: {path}:{line_no} unparsable ({exc})",
                          file=sys.stderr)
    rows.sort(key=lambda r: r["_ts"])
    return rows


def counter_deltas(rows, start, end):
    """Sum monotonic counter deltas inside [start, end]."""
    totals = collections.Counter()
    previous = {}
    for row in rows:
        in_window = (start is None or row["_ts"] >= start) and \
                    (end is None or row["_ts"] <= end)
        for name, val in row["counters"].items():
            packets = val["packets"]
            prev = previous.get(name)
            if prev is None:
                delta = 0                 # first observation = baseline
            elif packets < prev:
                delta = packets           # counter reset, count from zero
            else:
                delta = packets - prev
            previous[name] = packets
            if in_window:
                totals[name] += delta
    return totals


def unique_ips(node_dir):
    """Union of all daily IPv4 dumps = unique sources over the whole run.

    The dynamic set has a 30d timeout, so a single dump can miss early
    scanners on a long run; the union across dumps is the honest number.
    """
    seen = set()
    for path in sorted((node_dir / "ipdump").glob("*-v4.json.gz")):
        try:
            with gzip.open(path, "rt") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"  warn: {path} unreadable ({exc})", file=sys.stderr)
            continue
        for obj in doc.get("nftables", []):
            s = obj.get("set")
            if not s:
                continue
            for elem in s.get("elem", []):
                if isinstance(elem, dict) and "elem" in elem:
                    seen.add(elem["elem"].get("val"))
                else:
                    seen.add(elem)
    seen.discard(None)
    return seen


def read_opencanary(node_dir, start, end):
    """Event counts, credentials and HTTP paths from the OpenCanary log."""
    stats = {
        "events": 0,
        "by_logtype": collections.Counter(),
        "credentials": collections.Counter(),
        "http_paths": collections.Counter(),
        "user_agents": collections.Counter(),
        "src_hosts": set(),
        "first_event": None,
    }
    log = node_dir / "opencanary" / "opencanary.log"
    if not log.exists():
        return stats
    with log.open(errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            ts = ev.get("local_time_adjusted") or ev.get("local_time")
            when = None
            if ts:
                try:
                    when = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
                except ValueError:
                    when = None
            if when is not None:
                if start is not None and when < start:
                    continue
                if end is not None and when > end:
                    continue
                if stats["first_event"] is None or when < stats["first_event"]:
                    stats["first_event"] = when
            stats["events"] += 1
            stats["by_logtype"][str(ev.get("logtype"))] += 1
            if ev.get("src_host"):
                stats["src_hosts"].add(ev["src_host"])
            data = ev.get("logdata") or {}
            user = data.get("USERNAME")
            pwd = data.get("PASSWORD")
            if user is not None or pwd is not None:
                stats["credentials"][f"{user}:{pwd}"] += 1
            if data.get("PATH"):
                stats["http_paths"][data["PATH"]] += 1
            if data.get("USERAGENT"):
                stats["user_agents"][data["USERAGENT"]] += 1
    return stats


def top(counter, n=10):
    return counter.most_common(n)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("data_dir", help="collector directory (see bin/collect.sh)")
    ap.add_argument("--start", help="measurement window start (ISO-8601 UTC)")
    ap.add_argument("--end", help="measurement window end (ISO-8601 UTC)")
    ap.add_argument("--csv", help="write per-node per-port totals to this CSV")
    ap.add_argument("--top", type=int, default=10, help="top-N list length")
    args = ap.parse_args()

    start = parse_ts(args.start) if args.start else None
    end = parse_ts(args.end) if args.end else None

    root = pathlib.Path(args.data_dir)
    nodes = sorted(p for p in root.iterdir() if (p / "snapshots").is_dir())
    if not nodes:
        print(f"no node directories with snapshots/ under {root}", file=sys.stderr)
        return 1

    results = {}
    for node_dir in nodes:
        node = node_dir.name
        rows = read_snapshots(node_dir)
        results[node] = {
            "snapshots": len(rows),
            "first_snapshot": rows[0]["_ts"] if rows else None,
            "last_snapshot": rows[-1]["_ts"] if rows else None,
            "counters": counter_deltas(rows, start, end),
            "unique_ips": unique_ips(node_dir),
            "canary": read_opencanary(node_dir, start, end),
        }

    window = f"{start or 'begin'} .. {end or 'end'}"
    print(f"Measurement window: {window}\n")

    print(f"{'node':<14}{'SYN total':>12}{'unique src':>12}"
          f"{'canary ev':>11}{'canary src':>12}  first canary event")
    for node, r in results.items():
        syn = sum(v for k, v in r["counters"].items() if k.startswith("c_t"))
        first = r["canary"]["first_event"]
        print(f"{node:<14}{syn:>12}{len(r['unique_ips']):>12}"
              f"{r['canary']['events']:>11}{len(r['canary']['src_hosts']):>12}"
              f"  {first.isoformat() if first else '-'}")

    all_ports = sorted(
        {k for r in results.values() for k in r["counters"] if k.startswith("c_t")},
        key=lambda k: (0, int(k[3:])) if k[3:].isdigit() else (1, 0),
    )
    print("\nSYN packets per TCP port")
    print(f"{'port':<12}" + "".join(f"{n:>16}" for n in results))
    for key in all_ports:
        label = key[3:] if key[3:].isdigit() else key[2:]
        print(f"{label:<12}" + "".join(
            f"{results[n]['counters'].get(key, 0):>16}" for n in results))

    for node, r in results.items():
        print(f"\n=== {node} ===")
        c = r["canary"]
        print(f"  snapshots: {r['snapshots']} "
              f"({r['first_snapshot']} .. {r['last_snapshot']})")
        print(f"  event types: {dict(c['by_logtype'])}")
        if c["credentials"]:
            print("  top credentials:")
            for cred, n in top(c["credentials"], args.top):
                print(f"    {n:>8}  {cred}")
        if c["http_paths"]:
            print("  top HTTP paths:")
            for path, n in top(c["http_paths"], args.top):
                print(f"    {n:>8}  {path}")
        if c["user_agents"]:
            print("  top user agents:")
            for ua, n in top(c["user_agents"], args.top):
                print(f"    {n:>8}  {ua}")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["node", "counter", "packets"])
            for node, r in results.items():
                for key, val in sorted(r["counters"].items()):
                    w.writerow([node, key, val])
        print(f"\nCSV written to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
