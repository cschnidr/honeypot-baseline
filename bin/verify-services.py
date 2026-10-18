#!/usr/bin/env python3
"""Verify from OUTSIDE that every node's emulated services actually ANSWER.

verify-exposure.sh checks that the ports are open. That is not enough: a module
that accepts the TCP connection and then writes nothing looks identical to a
healthy one from the outside, and from the inside it looks healthy too - the
port is bound, the container has not restarted, and the module still logs
connection events. A honeypot in that state is skipped by attackers after the
first attempt, so its traffic volume collapses for reasons that have nothing to
do with the network in front of it. That failure mode silently invalidated a
12-day measurement window, which is why this check exists.

    ./verify-services.py 203.0.113.7 198.51.100.9
    ./verify-services.py --json <ip> <ip>          # machine-readable
    ./verify-services.py --interval 3600 <ip> ...  # keep probing (liveness)

Exits non-zero when any check fails, or when two nodes disagree - the nodes are
then not comparable and the measurement window is void.

Deliberately banner-only: no login is ever submitted, so this probe cannot
contaminate the credential dimension. It does create one connection event per
service per run, logged with this machine's source address - pass that address
to analyze.py --exclude-src.
"""

import argparse
import json
import socket
import sys
import time

CONNECT_TIMEOUT = 4.0
READ_TIMEOUT = 3.0
ATTEMPTS = 2

# X.224 Connection Request. A live RDP module answers with a Connection Confirm
# (19 bytes, same TPKT header); a dead one accepts the connection and is silent.
X224 = bytes.fromhex("030000130ed00000123400020008000000000000")[:19]
HTTP_GET = b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n"

# name, port, payload (None = connect-only, protocol sends no banner), verifier
CHECKS = (
    ("ftp", 21, b"", lambda d: d.startswith(b"220")),
    ("ssh", 22, b"", lambda d: d.startswith(b"SSH-2.0-")),
    ("telnet", 23, b"", lambda d: d[:1] == b"\xff"),
    ("http", 80, HTTP_GET, lambda d: b" 302 " in d[:40]),
    ("mssql", 1433, None, None),
    ("mysql", 3306, b"", lambda d: b"5.7" in d[:48]),
    ("rdp", 3389, X224, lambda d: d.startswith(b"\x03\x00\x00\x13")),
    ("vnc", 5900, b"", lambda d: d.startswith(b"RFB ")),
    ("redis", 6379, b"PING\r\n", lambda d: b"NOAUTH" in d or b"PONG" in d),
    ("httpproxy", 8080, HTTP_GET, lambda d: b" 407 " in d[:40]),
    ("git", 9418, None, None),
)


def attempt(ip, port, payload, verify):
    """One connection. Returns (ok, detail)."""
    try:
        sock = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        return False, "connect: %s" % (getattr(exc, "strerror", None) or type(exc).__name__)
    try:
        if payload is None:
            return True, "tcp open"
        if payload:
            sock.sendall(payload)
        sock.settimeout(READ_TIMEOUT)
        data = b""
        deadline = time.monotonic() + READ_TIMEOUT
        while len(data) < 64 and time.monotonic() < deadline:
            try:
                chunk = sock.recv(64 - len(data))
            except socket.timeout:
                break
            except OSError as exc:
                return False, "read: %s" % type(exc).__name__
            if not chunk:
                break
            data += chunk
        if not data:
            return False, "no answer"
        if verify(data):
            return True, "ok"
        return False, "unexpected: %s" % data[:24].decode("latin1").strip()
    finally:
        sock.close()


def probe(ip, port, payload, verify):
    """ATTEMPTS tries, because a single miss is a measurement error, not a fault."""
    detail = "not run"
    for _ in range(ATTEMPTS):
        ok, detail = attempt(ip, port, payload, verify)
        if ok:
            return True, detail
    return False, detail


def run_once(hosts):
    results = {}
    for ip in hosts:
        node = {}
        for name, port, payload, verify in CHECKS:
            ok, detail = probe(ip, port, payload, verify)
            node[name] = {"port": port, "ok": ok, "detail": detail}
        results[ip] = node
    return results


def report(hosts, results):
    """Print a matrix and return (failures, mismatches)."""
    failures = []
    mismatches = []
    print("%-11s%-7s" % ("SERVICE", "PORT"), end="")
    for ip in hosts:
        print("%-22s" % ip, end="")
    print()
    for name, port, _payload, _verify in CHECKS:
        print("%-11s%-7d" % (name, port), end="")
        states = []
        for ip in hosts:
            r = results[ip][name]
            states.append(r["ok"])
            print("%-22s" % (r["detail"][:21]), end="")
            if not r["ok"]:
                failures.append("%s %s/%d: %s" % (ip, name, port, r["detail"]))
        print()
        if len(set(states)) > 1:
            mismatches.append(
                "%s/%d: %s"
                % (name, port, ", ".join("%s=%s" % (ip, "ok" if results[ip][name]["ok"] else "FAIL")
                                         for ip in hosts))
            )
    return failures, mismatches


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", nargs="+", help="node IP addresses")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--interval", type=int, metavar="SECS",
                    help="keep probing every SECS instead of exiting (liveness mode)")
    args = ap.parse_args()

    while True:
        results = run_once(args.hosts)
        if args.json:
            print(json.dumps({"checked_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                              "results": results}, indent=1, sort_keys=True))
            failures = [
                "%s %s/%d: %s" % (ip, name, r["port"], r["detail"])
                for ip, node in results.items() for name, r in node.items() if not r["ok"]
            ]
            mismatches = []
        else:
            failures, mismatches = report(args.hosts, results)
            print()
            if failures:
                print("FAILED:")
                for f in failures:
                    print("  " + f)
            if mismatches:
                print("NODES DISAGREE - not comparable:")
                for m in mismatches:
                    print("  " + m)
            if not failures and not mismatches:
                print("OK - every service answers on every node.")

        if args.interval is None:
            return 1 if (failures or mismatches) else 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
