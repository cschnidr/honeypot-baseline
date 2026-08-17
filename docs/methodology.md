# Measurement design

The point of this kit is not to run a honeypot — that is easy — but to run
*several* honeypots whose numbers can be compared without arguing about the
setup afterwards. Everything below exists to remove an alternative explanation
for a difference between hosts.

## The one rule

**One script, run identically everywhere.** `bootstrap.sh` contains every
decision that affects a host's behaviour, so "same file, same conditions" is
enforceable rather than aspirational. If you need a per-host tweak, that tweak
is a variable in your experiment — write it down in the host's `manifest.txt`.

| Held constant | Varied |
|---|---|
| OS image (Debian 13, x86_64) | host / provider / network |
| Honeypot software (one image, distributed as a tar) | — |
| Emulated port set (11 TCP ports) | — |
| Counted port set (25 TCP + 8 UDP) | — |
| Firewall policy (`drop`) and rule order | — |
| Clock (UTC, chrony) | — |

Match everything else you reasonably can. If you compare hosting providers,
pick nearby regions — scan volume varies geographically, and you do not want
region and provider varying together.

## Confounders and how they are handled

**Address reputation.** Some address ranges are scanned far more than others,
independent of anything you did. With a single comparison host you cannot tell
"this range is quiet" from a real effect. Mitigation: at least two comparable
hosts on different providers.

**Recycled cloud addresses.** A freshly allocated address can inherit residual
traffic aimed at the previous tenant's services. Mitigation: 48h burn-in after
allocation, excluded from the measurement window via `--start`, and allocation
times recorded per host in `manifest.txt`.

**Docker's own netfilter rules.** With bridge networking and published ports,
inbound traffic is DNATed in `PREROUTING` and traverses the forward path, so
input-hook counters miss it — and the exact behaviour differs between Docker
versions, which would make the error *vary per host*. Mitigation:
`network_mode: host`, so there is no DNAT and every packet is counted once.
This is the single easiest way to get silently wrong numbers.

**Provider-side or host-side filtering.** Managed firewalls, IDS/IPS offerings,
"threat protection" add-ons and platform-level scan blocking all change what
reaches the host. Either disable them everywhere, or enable them identically
everywhere, and record which in `manifest.txt`. Note that some platform-level
filtering cannot be disabled or even observed by a customer — if that is what
you are investigating, say so explicitly and treat the result as inferential.

**Residential versus datacenter.** A home line varies network type, address
reputation and ASN prominence at once. It is a separate data point, not a
control group.

**Filtered versus closed ports.** Chain policy is `drop`, so non-emulated ports
appear *filtered* rather than *closed* (no RST). Identical across hosts and
therefore internally comparable, but absolute numbers are not directly
comparable with studies whose hosts return RST, because scanners follow up
differently.

**Time.** Botnet campaigns start and stop. A three-week window is one sample of
a non-stationary process, and a single large campaign can dominate it. All hosts
must run the *same* window — that is what `--start` / `--end` enforce.

## Metrics

| Metric | Source |
|---|---|
| SYN packets per TCP port per day | nftables named counters |
| UDP packets per port per day | nftables named counters |
| Unique source IPv4/IPv6 addresses | nftables dynamic sets, daily dumps |
| Time to first contact after go-live | first OpenCanary event / first counter delta |
| Credentials attempted | OpenCanary `logdata.USERNAME/PASSWORD` |
| HTTP request paths and user agents | OpenCanary `logdata.PATH/USERAGENT` |
| Event mix per protocol | OpenCanary `logtype` |

Counters record **raw SYN packets including retransmits**, not conntrack
entries. That avoids conntrack pressure under load, but the number means "SYN
packets", not "connection attempts" — state it that way in any write-up.

Counters are monotonic. `bin/analyze.py` sums deltas between consecutive
snapshots and treats a backwards step (reboot, ruleset reload) as a reset.

The unique-source sets have a 30-day timeout, so a single reading can miss early
scanners on a long run. `analyze.py` therefore unions all daily dumps rather
than trusting the last count.

## Before the measurement window

1. `bin/verify-exposure.sh` from a machine **outside** `ADMIN_CIDR` — the port
   lists must be identical. A host with a different port state makes the
   comparison void for that port.
2. Compare `manifest.txt` across hosts: the config and ruleset hashes and the
   Docker image ID must match.
3. 48h burn-in, excluded from the window.
4. Record the window start and each host's allocation time.

## Limitations to state in any write-up

- n=1 host per condition. Differences between two hosts are observations, not
  measured effects with confidence intervals.
- Three weeks is a single sample of a time-varying process.
- Anything happening upstream of the host (platform filtering, transit-level
  blocking) is invisible from the inside; attribution stays inferential.
- A null result is weak evidence. It can equally mean the measured traffic class
  is not the one affected by whatever you were looking for.

The valuable output of a run like this is a well-characterised measurement with
its caveats intact — not a verdict.
