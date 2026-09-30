#!/usr/bin/env python3
"""Aggregate the collected honeypot data into comparable per-node numbers.

Input is the collector directory produced by bin/collect.sh:

    data/<node>/snapshots/<node>-<YYYY-MM-DD>.jsonl
    data/<node>/ipdump/<node>-<YYYY-MM-DD>-v4.json.gz
    data/<node>/synlog/<node>-<YYYYmmddTHHMMSS>.pcap[.gz]
    data/<node>/opencanary/opencanary.log
    data/<node>/manifest.txt

Usage:
    analyze.py data/ --start 2026-08-19T00:00:00Z --end 2026-09-09T00:00:00Z
    analyze.py data/ --csv out.csv
    analyze.py data/ --start ... --end ... --cutoff host-a,host-b

--cutoff A,B runs the per-source cut-off analysis on the hp-synlog pcaps: A is
the host whose provider claims automatic scanner restriction, B the comparison
host. Thresholds are fixed constants (pre-registered), not options.

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
import ipaddress
import json
import pathlib
import re
import struct
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


DUMP_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})-v4\.json\.gz$")


def unique_ips(node_dir, start=None, end=None):
    """Union of the daily IPv4 dumps inside [start, end] = unique sources.

    The dynamic set has a 30d timeout, so a single dump can miss early
    scanners on a long run; the union across dumps is the honest number.

    Dumps are written at 00:00 UTC and named by that date. Only dumps whose
    date falls inside the window are used, so burn-in dumps (and dumps from a
    host that started earlier than the others) cannot inflate the count. The
    resolution is one day. For a clean start, flush the scan sets on every
    host at the window start (see docs/methodology.md).
    """
    seen = set()
    for path in sorted((node_dir / "ipdump").glob("*-v4.json.gz")):
        m = DUMP_DATE.search(path.name)
        if m and (start is not None or end is not None):
            when = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if (start is not None and when < start) or (end is not None and when > end):
                continue
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


# --- hp-synlog: per-source SYN timelines from the hourly pcaps ---------------

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
SYNLOG_NAME = re.compile(r"-(\d{8}T\d{6})\.pcap(\.gz)?$")


def _l3_offset(linktype, pkt):
    """Byte offset of the IP header for the link types tcpdump writes."""
    if linktype == 1:                     # Ethernet, skip VLAN tags
        off, etype = 14, int.from_bytes(pkt[12:14], "big")
        while etype in (0x8100, 0x88A8) and len(pkt) >= off + 4:
            etype = int.from_bytes(pkt[off + 2:off + 4], "big")
            off += 4
        return off
    if linktype == 113:                   # Linux cooked v1
        return 16
    if linktype == 276:                   # Linux cooked v2
        return 20
    if linktype in (12, 101):             # raw IP
        return 0
    return None


def _parse_syn(linktype, pkt):
    """Return (src, dport) for a TCP SYN without ACK, else None."""
    off = _l3_offset(linktype, pkt)
    if off is None or len(pkt) < off + 20:
        return None
    ver = pkt[off] >> 4
    if ver == 4:
        ihl = (pkt[off] & 0x0F) * 4
        if pkt[off + 9] != 6:
            return None
        src = ".".join(str(b) for b in pkt[off + 12:off + 16])
        tcp = off + ihl
    elif ver == 6:
        if len(pkt) < off + 40 or pkt[off + 6] != 6:
            return None                   # extension headers are not decoded
        src = str(ipaddress.IPv6Address(bytes(pkt[off + 8:off + 24])))
        tcp = off + 40
    else:
        return None
    if len(pkt) < tcp + 14:
        return None
    if pkt[tcp + 13] & 0x12 != 0x02:      # SYN set, ACK clear
        return None
    return src, int.from_bytes(pkt[tcp + 2:tcp + 4], "big")


def read_pcap(path):
    """Yield (epoch_seconds, src, dport) for every SYN in a pcap(.gz).

    Tolerates a truncated final record (file still being written or rsynced
    mid-write).
    """
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24 or head[:4] not in PCAP_MAGIC:
            print(f"  warn: {path} is not a pcap", file=sys.stderr)
            return
        endian, unit = PCAP_MAGIC[head[:4]]
        linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
        rec = struct.Struct(endian + "IIII")
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                return
            sec, frac, incl, _orig = rec.unpack(hdr)
            pkt = fh.read(incl)
            if len(pkt) < incl:
                return
            hit = _parse_syn(linktype, pkt)
            if hit:
                yield sec + frac * unit, hit[0], hit[1]


def read_synlog(node_dir, start, end):
    """Per-source SYN timeline inside [start, end].

    Returns {src: {"ts": [sorted epoch seconds], "ports": set}} or None when
    the node has no synlog directory.
    """
    d = node_dir / "synlog"
    if not d.is_dir():
        return None
    t0 = start.timestamp() if start else float("-inf")
    t1 = end.timestamp() if end else float("inf")
    srcs = {}
    for path in sorted(d.glob("*.pcap*")):
        m = SYNLOG_NAME.search(path.name)
        if m:                             # skip files that start after the window
            fstart = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
            if fstart.timestamp() > t1:
                continue
        try:
            for ts, src, dport in read_pcap(path):
                if t0 <= ts <= t1:
                    s = srcs.setdefault(src, {"ts": [], "ports": set()})
                    s["ts"].append(ts)
                    s["ports"].add(dport)
        except (OSError, EOFError) as exc:
            print(f"  warn: {path} unreadable ({exc})", file=sys.stderr)
    for s in srcs.values():
        s["ts"].sort()
    return srcs


# Pre-registered thresholds (NOTES.local.md, 2026-09-30). Do not tune these
# after looking at window data.
MIN_SYNS = 3          # a source counts at a host with >= 3 SYNs there
OUTLIVE_GAP = 3600    # "outlived": >= MIN_SYNS SYNs at the other host > 60 min later
MAX_SPAN = 1800       # supported needs median A-span of outlived-at-B sources <= 30 min
MIN_SHARED = 200      # fewer shared sources -> inconclusive
HEAVY_PORTS = 10      # heavy scanner: >= 10 distinct destination ports at one host


def _outlived(later, earlier_last):
    """True if `later` has >= MIN_SYNS timestamps more than OUTLIVE_GAP after earlier_last."""
    cut = earlier_last + OUTLIVE_GAP
    return sum(1 for t in later if t > cut) >= MIN_SYNS


def cutoff_report(a_name, a, b_name, b):
    """H1 (per-source cut-off asymmetry) and H2 (heavy scanners) for hosts A, B.

    A is the host whose provider claims fast automatic restriction.
    """
    out = {}
    shared = [s for s in a if s in b
              and len(a[s]["ts"]) >= MIN_SYNS and len(b[s]["ts"]) >= MIN_SYNS]
    out["shared"] = len(shared)
    at_b = [s for s in shared if _outlived(b[s]["ts"], a[s]["ts"][-1])]
    at_a = [s for s in shared if _outlived(a[s]["ts"], b[s]["ts"][-1])]
    out["outlived_at_b"], out["outlived_at_a"] = len(at_b), len(at_a)
    share_b = len(at_b) / len(shared) if shared else 0.0
    share_a = len(at_a) / len(shared) if shared else 0.0
    out["share_b"], out["share_a"] = share_b, share_a
    if share_a:
        out["R"] = share_b / share_a
    else:
        out["R"] = float("inf") if share_b else None
    spans = sorted(a[s]["ts"][-1] - a[s]["ts"][0] for s in at_b)
    out["median_a_span_outlived_b"] = spans[len(spans) // 2] if spans else None
    hits_a = sorted(len(a[s]["ts"]) for s in shared)
    hits_b = sorted(len(b[s]["ts"]) for s in shared)
    out["median_hits_a"] = hits_a[len(hits_a) // 2] if hits_a else None
    out["median_hits_b"] = hits_b[len(hits_b) // 2] if hits_b else None

    R, span = out["R"], out["median_a_span_outlived_b"]
    if len(shared) < MIN_SHARED or R is None:
        out["h1"] = "INCONCLUSIVE"
    elif R >= 2 and span is not None and span <= MAX_SPAN:
        out["h1"] = "SUPPORTED"
    elif R <= 0.5:
        out["h1"] = "CONTRADICTED"
    else:
        out["h1"] = "INCONCLUSIVE"

    heavy_a = {s for s, v in a.items() if len(v["ports"]) >= HEAVY_PORTS}
    heavy_b = {s for s, v in b.items() if len(v["ports"]) >= HEAVY_PORTS}
    out["heavy_a"], out["heavy_b"] = len(heavy_a), len(heavy_b)
    out["heavy_only_a"] = len([s for s in heavy_a if s not in b])
    out["heavy_only_b"] = len([s for s in heavy_b if s not in a])
    oa, ob = out["heavy_only_a"], out["heavy_only_b"]
    out["h2"] = "SUPPORTED" if ob >= 2 * max(oa, 1) else "NOT SUPPORTED"
    return out


def print_cutoff(a_name, b_name, r):
    fmt_min = lambda s: f"{s / 60:.1f} min" if s is not None else "-"
    fmt_r = "-" if r["R"] is None else ("inf" if r["R"] == float("inf") else f"{r['R']:.2f}")
    print(f"\nPer-source cut-off analysis  A={a_name}  B={b_name}  (pre-registered)")
    print(f"  shared sources (>= {MIN_SYNS} SYNs at both): {r['shared']}")
    print(f"  median SYNs per shared source: A={r['median_hits_a']}  B={r['median_hits_b']}"
          "   <- unequal hit rates bias R, report them")
    print(f"  outlived at B (still at {b_name} > 60 min after last seen at {a_name}): "
          f"{r['outlived_at_b']} ({r['share_b']:.1%})")
    print(f"  outlived at A (symmetric): {r['outlived_at_a']} ({r['share_a']:.1%})")
    print(f"  R = {fmt_r}   median {a_name} active span of outlived-at-B sources: "
          f"{fmt_min(r['median_a_span_outlived_b'])}")
    print(f"  H1 (R >= 2 and span <= 30 min; contradicted R <= 0.5; n >= {MIN_SHARED}): {r['h1']}")
    print(f"  heavy scanners (>= {HEAVY_PORTS} ports): A={r['heavy_a']} B={r['heavy_b']}  "
          f"only-A={r['heavy_only_a']} only-B={r['heavy_only_b']}")
    print(f"  H2 (only-B >= 2x only-A): {r['h2']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("data_dir", help="collector directory (see bin/collect.sh)")
    ap.add_argument("--start", help="measurement window start (ISO-8601 UTC)")
    ap.add_argument("--end", help="measurement window end (ISO-8601 UTC)")
    ap.add_argument("--csv", help="write per-node per-port totals to this CSV")
    ap.add_argument("--top", type=int, default=10, help="top-N list length")
    ap.add_argument("--cutoff", metavar="A,B",
                    help="per-source cut-off analysis on hp-synlog pcaps; "
                         "A = host with claimed restriction, B = comparison host")
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
            "unique_ips": unique_ips(node_dir, start, end),
            "canary": read_opencanary(node_dir, start, end),
            "synlog": read_synlog(node_dir, start, end),
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
        s = r["synlog"]
        if s is not None:
            print(f"  synlog: {sum(len(v['ts']) for v in s.values())} SYNs "
                  f"from {len(s)} sources")

    if args.cutoff:
        names = [n.strip() for n in args.cutoff.split(",")]
        if len(names) != 2 or any(n not in results for n in names):
            print(f"--cutoff needs two node names from: {', '.join(results)}",
                  file=sys.stderr)
            return 1
        a_name, b_name = names
        a, b = results[a_name]["synlog"], results[b_name]["synlog"]
        if a is None or b is None:
            print("--cutoff: both nodes need a synlog/ directory", file=sys.stderr)
            return 1
        print_cutoff(a_name, b_name, cutoff_report(a_name, a, b_name, b))

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
