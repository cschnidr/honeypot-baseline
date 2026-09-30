# AGENTS.md

Guidance for AI agents working in this repository. Everything here is derived
from the actual files in the repo — verify against source before extending it.

## Overview

`honeypot-baseline` is a small, reproducible honeypot deployment kit for
**comparing inbound attack traffic across several hosts**. The design goal is
that every host runs an *identical* setup — one bootstrap script, one container
image distributed as a tar, one fixed port contract — so that differences in the
collected numbers reflect the hosts, not the configuration.

Two measurement layers:

- **Layer 1 — nftables on the host.** Per-port SYN counters (25 TCP ports),
  UDP packet counters (8 ports), and two dynamic sets collecting unique source
  addresses with a 30-day timeout. Volume and diversity signal.
- **Layer 2 — OpenCanary in a container.** Emulates 11 TCP services and logs
  credentials, HTTP paths and user agents as JSON. Content signal.

There is no database, agent, or dashboard by design. Data is plain JSON/JSONL on
disk; analysis is a single stdlib-only Python script.

Status (per `README.md`): written and syntax-checked, **not yet deployed**.

## Repo layout

| Path | Responsibility |
|---|---|
| `bootstrap.sh` | Per-host setup, run identically on every node. Installs packages, moves SSH to port 62222, builds/loads the nftables `hp` table, loads/builds the OpenCanary image, starts the container, installs snapshot timers, writes a fingerprint manifest. |
| `opencanary/Dockerfile` | Builds the `honeypot-opencanary:pinned` image (Python 3.12 slim + `pip install opencanary`). Built once, distributed via `docker save`/`load`. |
| `opencanary/opencanary.conf` | Config template with `__NODE_ID__` placeholder. 11 emulated TCP services; UDP amplification modules (ntp/snmp/sip/tftp) deliberately disabled. |
| `bin/snapshot.sh` | Installed on-node as `hp-snapshot`. Dumps nft counters/sets to JSON and appends one JSONL record via `hp_snapshot.py`. `--ipdump` also gzips the full source-IP list. |
| `bin/hp_snapshot.py` | Pure transform: reads nft JSON, prints exactly one JSON object. No side effects. |
| `bin/analyze.py` | Collector-side aggregation and comparison report. Stdlib only. Computes counter deltas, unions daily IP dumps, parses the OpenCanary log. |
| `bin/collect.sh` | rsync puller run from the collector machine. Pull-only, never writes to nodes. |
| `bin/verify-exposure.sh` | External check that all hosts expose an identical port set. Run before trusting any comparison. |
| `testdata/` | nft JSON fixtures (`counters.json`, `scan4.json`, `scan6.json`) for exercising `hp_snapshot.py`. |
| `docs/methodology.md` | Measurement design, confounders, limitations. |
| `docs/analysis.md` | Data formats and how to read the output. |

## Languages, build, test, lint

There is **no build system, package manifest, or test runner** in this repo
(no `Makefile`, `package.json`, `pyproject.toml`, `requirements.txt`, or CI
config). It is a collection of Bash scripts and stdlib-only Python 3 scripts.

The Python scripts have **no third-party dependencies** — `analyze.py` and
`hp_snapshot.py` import only the standard library.

Verification commands that work in a plain checkout (no root, no Docker, no
nftables required):

```bash
# Syntax-check every shell script
for f in bootstrap.sh bin/*.sh; do bash -n "$f" && echo "ok: $f"; done

# Byte-compile the Python scripts (syntax check)
python3 -m py_compile bin/hp_snapshot.py bin/analyze.py

# Exercise hp_snapshot.py against the checked-in fixtures
python3 bin/hp_snapshot.py host-a 20260816T210000Z \
    testdata/counters.json testdata/scan4.json testdata/scan6.json
```

`hp_snapshot.py` prints exactly one JSON object; a clean exit and valid JSON is
the pass signal.

Commands that require a real deployment target (Debian 13, root, systemd,
Docker, nftables) and will **not** run on a dev laptop:

- `bootstrap.sh` — must run as root on Debian; it self-gates with
  `nft -c -f` before applying the ruleset and aborts if SSH is not on the new
  port first.
- `bin/snapshot.sh` — reads live `nft` tables.
- Any `docker` / `nft` / `systemctl` invocation.

`bin/analyze.py` and `bin/collect.sh` run on a collector machine against
collected data; `analyze.py` can run anywhere Python 3 exists given a populated
`data/` directory.

## Conventions

- **Shell:** `#!/usr/bin/env bash` with `set -euo pipefail` (scripts that must
  not abort mid-probe, like `verify-exposure.sh`, use `set -uo pipefail`).
  Config via environment variables with `${VAR:?message}` for required inputs
  and `${VAR:-default}` for optional ones. `log()`/`die()` helpers for output.
- **Python:** stdlib only, module docstring with usage, `main(argv)` returning
  an exit code, guarded by `if __name__ == "__main__"`. Keep it dependency-free.
- **The port contract is load-bearing.** `HP_TCP`, `CNT_TCP`, `CNT_UDP` in
  `bootstrap.sh`, the `PORTS` array in `verify-exposure.sh`, and the enabled
  services in `opencanary.conf` describe the same contract. If you change ports
  in one place, change them everywhere and re-verify — a mismatch silently
  invalidates every cross-host comparison.
- **Counter naming:** `c_t<port>` (TCP), `c_u<port>` (UDP), plus `c_tcp_other`,
  `c_udp_other`, `c_udp_bcast`, `c_icmp`. `analyze.py` relies on the `c_t`
  prefix to sum SYNs. `c_u<port>`/`c_udp_other` are unicast-only
  (`meta pkttype host`); broadcast/multicast UDP is bucketed in `c_udp_bcast`
  and is a per-host environment characteristic, not a scan signal.
- Reproducibility is the whole point: the image is built once and shipped as
  `image.tar`; identity is the recorded Docker image ID in each node's manifest,
  not a version tag.

## Safety / gotchas

- **This deploys an intentionally exposed host.** Read the Safety section of
  `README.md` before changing anything that affects what is exposed.
- **No amplification, no outbound fetching.** ntp/snmp/sip/tftp stay disabled in
  `opencanary.conf` (UDP reflection vectors); OpenCanary never executes or
  downloads attacker payloads. Do not enable modules that reply on UDP
  amplification ports or that fetch samples.
- **`network_mode: host` is required** for the input-hook counters to see
  traffic — this removes container network isolation, so real host/VPC/VLAN
  isolation is the actual boundary.
- **A wrong `ADMIN_CIDR` locks the host out.** `bootstrap.sh` moves SSH to
  62222 and aborts before touching the firewall if SSH is not confirmed on the
  new port. Keep out-of-band console access ready when testing on a real host.
- **Collected data contains third-party IP addresses.** `data/`, `nodes.txt`,
  `image.tar`, `results.csv`, `*.png` and `NOTES.local.md` are gitignored — keep
  it that way. Never commit measurement data or a node list.
- **Counters are cumulative;** `analyze.py` treats a decrease as a reset. Don't
  "fix" that into naive subtraction.
- **Docker packaging on Debian 13:** `docker-cli` and `docker-compose` are only
  *Recommends* of `docker.io`, so `bootstrap.sh`'s `--no-install-recommends`
  requires them to be named explicitly in the install list (they are). Without
  them the `docker` CLI / `docker compose` subcommand are missing and the image
  build fails with `docker: command not found`. On trixie `docker-compose` is
  Compose v2.

## How to verify a change

1. Run the syntax/compile checks above; all shell scripts and Python scripts
   must pass.
2. If you touched `hp_snapshot.py` or the data schema, run it against
   `testdata/` and confirm the emitted JSON still matches the format documented
   in `docs/analysis.md`.
3. If you touched the port contract, confirm `HP_TCP`/`CNT_TCP`/`CNT_UDP`
   (bootstrap), the `PORTS` array (verify-exposure), and the enabled services
   (opencanary.conf) still agree.
4. If you touched `bootstrap.sh`, remember it can only be fully exercised as
   root on Debian 13; note in your change what you could and could not verify
   locally.
