# Data formats and analysis

## On-node layout

| Path | Content |
|---|---|
| `/var/lib/honeypot/snapshots/<node>-<YYYY-MM-DD>.jsonl` | hourly counter snapshots |
| `/var/lib/honeypot/ipdump/<node>-<YYYY-MM-DD>-v4.json.gz` | daily full unique-source dump |
| `/var/lib/honeypot/manifest.txt` | host fingerprint (hashes, image ID, port lists) |
| `/var/log/opencanary/opencanary.log` | one JSON object per service interaction |
| `/etc/honeypot-node-id` | the node's `NODE_ID` |

### Snapshot record

One JSON object per line, written hourly by `hp-snapshot`:

```json
{
  "node": "host-a",
  "ts": "20260816T210000Z",
  "unique_src_v4": 4213,
  "unique_src_v6": 7,
  "counters": {
    "c_t22":       {"packets": 18422, "bytes": 1105320},
    "c_t443":      {"packets": 2210,  "bytes": 132600},
    "c_tcp_other": {"packets": 90113, "bytes": 5406780}
  }
}
```

Counter naming: `c_t<port>` for TCP, `c_u<port>` for UDP, plus `c_tcp_other`,
`c_udp_other` and `c_icmp` as catch-alls. Values are **cumulative** since the
ruleset was loaded.

`unique_src_v4` is the size of the dynamic nftables set at snapshot time. The
set has a 30-day timeout, so on a long run a single reading can miss early
scanners — `analyze.py` therefore unions all daily dumps rather than trusting
the last count.

### OpenCanary record

```json
{
  "dst_host": "10.0.0.5", "dst_port": 80,
  "src_host": "198.51.100.9", "src_port": 51514,
  "local_time": "2026-08-19 04:12:55.123456",
  "logtype": 3001, "node_id": "host-a",
  "logdata": {"PATH": "/.env", "USERAGENT": "Mozilla/5.0 zgrab/0.x"}
}
```

Credentials arrive as `logdata.USERNAME` / `logdata.PASSWORD`, HTTP detail as
`logdata.PATH` / `logdata.USERAGENT`. `logtype` identifies the module; the
mapping lives in OpenCanary's own source, and `analyze.py` reports raw values
rather than guessing at names.

## Collecting

`bin/collect.sh` pulls both trees to a collector machine. Node list format is
`<node_id> <ssh_target>` per line:

```
host-a  admin@198.51.100.10
host-b  root@203.0.113.20
home    me@192.168.1.20
```

```bash
./bin/collect.sh nodes.txt ./data      # SSH_PORT=62222 by default
```

Pull-only, `BatchMode=yes`, so it runs unattended from cron. Daily is plenty —
the whole dataset is a few MB.

## Analysing

```bash
./bin/analyze.py ./data \
    --start 2026-08-19T00:00:00Z \
    --end   2026-09-09T00:00:00Z \
    --csv   results.csv
```

`--start` / `--end` bound the measurement window; use them to drop the 48h
burn-in. Output is three blocks:

1. **Per-node summary** — total SYNs, unique sources, OpenCanary event count,
   distinct OpenCanary source hosts, first event timestamp
2. **SYN packets per TCP port**, nodes side by side — the table that answers
   the actual question
3. **Per-node detail** — event types, top credentials, top HTTP paths, top user
   agents

`--csv` writes long-format `node,counter,packets` for plotting elsewhere.
Standard library only, so it runs anywhere Python 3 does.

## Reading the result

Compare hosts of the **same class** with each other — two datacenter hosts, or
two residential lines. The residential host is a separate data point, not a
control for a datacenter one. Look at:

- **Total SYN volume.** A host that is materially lower or higher than *all*
  others is the headline observation. With only two hosts you cannot tell which
  one is the outlier.
- **Per-port shape.** A uniform difference across all ports suggests something
  broad (upstream filtering, address-range reputation). A difference
  concentrated on specific service ports points at targeted scanning for those
  services.
- **Unique sources versus volume.** Fewer unique sources at similar volume means
  a few noisy scanners; similar source counts at lower volume means per-source
  throttling somewhere. Different mechanisms, worth distinguishing.
- **HTTP paths.** The clearest signal of *what* is being looked for —
  `/.env`, framework admin paths, recent CVE probes.
- **Time to first contact.** How long a fresh address survives unnoticed.
- **Residential hosts separately.** Expect a different mix rather than simply
  less of the same.

Sanity checks before drawing any conclusion: every host has a comparable number
of snapshots, `manifest.txt` hashes match across hosts, and
`bin/verify-exposure.sh` passed at the start of the window. If any of those
fail, the volume comparison is not valid.
