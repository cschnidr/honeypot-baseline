# honeypot-baseline

A small, reproducible honeypot deployment for **comparing inbound attack traffic
across several hosts**. One script per host, one container image, one identical
port contract — so that differences in the collected numbers say something about
the *hosts* rather than about the setup.

Useful when you want to answer questions like:

- How much untargeted scan traffic does an internet-facing host actually see?
- Does that differ between hosting providers, networks, or a datacenter address
  versus a residential line?
- Which credentials, HTTP paths and exploit signatures show up, and how does the
  mix differ per host?

The kit stays deliberately small: nftables counters for volume, one container
for service emulation, plain JSON on disk, and a stdlib-only analysis script.
No agents, no database, no dashboard.

## What it measures

**Layer 1 — nftables on the host.** Per-port SYN counters on 25 TCP ports,
packet counters on 8 UDP ports, and two dynamic sets that collect every unique
source address with a 30-day timeout. This is the volume and diversity signal,
and it works on ports where nothing is listening.

**Layer 2 — OpenCanary in a container.** Emulates 11 TCP services and logs
credentials, HTTP request paths and user agents as JSON — the content signal:
*what* attackers try, not just how often.

Design reasoning, the confounders that matter and what the numbers can and
cannot support: [`docs/methodology.md`](docs/methodology.md).

## Hosts

Any number of hosts, each with its own `NODE_ID`. A useful minimum is three:

| `NODE_ID` | Example role |
|---|---|
| `host-a` | datacenter host, provider A |
| `host-b` | datacenter host, provider B |
| `home` | residential line (different network class) |

Two datacenter hosts rather than one, because the IP reputation of a single
provider range is itself a variable — with only one, an outlier is
indistinguishable from a real effect. A residential host is a useful third data
point but not a control group: it varies network type, address reputation and
ASN prominence all at once.

A small instance is plenty: the whole stack idles at a few tens of MB.

## Quick start

```bash
# 1. On the FIRST host: build the image and export it
sudo NODE_ID=host-a ADMIN_CIDR=<your-ip>/32 ./bootstrap.sh
docker save honeypot-opencanary:pinned -o image.tar

# 2. Copy the repo + image.tar to the other hosts, then run there:
sudo NODE_ID=host-b ADMIN_CIDR=<your-ip>/32 ./bootstrap.sh

# 3. From another machine, prove the hosts are comparable:
./bin/verify-exposure.sh <ip-a> <ip-b> <ip-c>

# 4. Burn in for 48h, then measure. Later, from the collector:
./bin/collect.sh nodes.txt ./data
./bin/analyze.py ./data --start 2026-08-19T00:00:00Z --end 2026-09-09T00:00:00Z
```

`image.tar` is what makes the hosts comparable: the image is built **once** and
distributed via `docker save` / `docker load`. A `:latest` tag pulled on four
hosts at four different times can be four different images.

`bootstrap.sh` is idempotent and does:

1. Packages (`nftables docker.io python3 jq rsync chrony`), UTC timezone, chrony
2. **Moves SSH to port 62222** (`MGMT_PORT`) so port 22 is free for the
   honeypot. Debian 13 uses `ssh.socket`, where the port lives in the socket
   unit and not in `sshd_config`; both cases are handled. The script **aborts**
   if SSH is not listening on the new port before the firewall takes effect.
3. nftables table `hp` — a dedicated table, no `flush ruleset`, so Docker's own
   rules survive — loaded by a unit ordered `After=docker.service`
4. Loads or builds the OpenCanary image, renders the config with `NODE_ID`,
   starts the container
5. systemd timers: hourly counter snapshot, daily unique-source dump
6. Fingerprint to `/var/lib/honeypot/manifest.txt` (SHA256 of config and
   ruleset, Docker image ID, kernel, port lists)

`NODE_ID` and `ADMIN_CIDR` are the only per-host variables. A wrong
`ADMIN_CIDR` locks the host out — keep out-of-band console access ready.

## Safety

**Read this before exposing anything.** A honeypot is a host you deliberately
let strangers connect to.

- **No amplification.** `ntp`, `snmp`, `sip` and `tftp` are **disabled** in
  OpenCanary. All four are UDP amplification vectors; a honeypot that answers on
  them turns the host into a reflector and earns abuse complaints. Those ports
  are still **counted** by nftables — counting without replying causes no
  amplification.
- **No outbound fetching.** OpenCanary emulates protocols and never executes
  attacker payloads or downloads samples. Tools that do (for example Dionaea's
  malware fetching) open outbound connections to malware hosts; if you add one,
  block its egress and expect provider abuse tickets.
- **Network isolation.** The host must not be able to reach anything you care
  about: a separate VLAN at home, a separate VPC or account with no peering in a
  cloud. Container namespaces are not the boundary here — `network_mode: host`
  is required for correct counting, which removes network namespace isolation.
- **Provider terms.** Passive honeypots are generally acceptable; running
  reflectors or scanning outward is not. Check your provider's AUP.
- **Collected data contains third-party addresses.** `data/` and `nodes.txt` are
  gitignored for a reason.

Port 443 is counted but not emulated (OpenCanary has no TLS listener), so there
are SYN counts on 443 but no request details. HTTP detail comes from ports 80
and 8080.

## Repo layout

```
bootstrap.sh                per-host setup, run identically everywhere
opencanary/Dockerfile       image, built once and distributed as a tar
opencanary/opencanary.conf  11 emulated TCP services, UDP modules off
bin/snapshot.sh             hourly counter snapshot + daily source dump
bin/hp_snapshot.py          nft JSON -> one JSONL record
bin/verify-exposure.sh      external check that all hosts expose equal ports
bin/collect.sh              rsync puller for the collector machine
bin/analyze.py              aggregation and comparison report
testdata/                   nft JSON fixtures for hp_snapshot.py
docs/methodology.md         measurement design, confounders, limitations
docs/analysis.md            data formats and how to read the output
```

## Status

Written and syntax-checked, **not yet deployed**. Verify on the first host:

- OpenCanary config keys (`http.skin`, `mssql.version`, module names) against
  the installed version — `opencanaryd --copyconfig` prints a reference config
- whether `pip install opencanary` completes with the build deps in the
  Dockerfile
- the `tcp dport != { ... }` rules against your nft version; `bootstrap.sh`
  gates on `nft -c -f` and aborts before applying anything

## License

MIT — see [`LICENSE`](LICENSE).
