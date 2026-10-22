# Window 2 rollout: enterprise lures + TLS

This is the rollout plan for the second measurement window. It merges two
prepared changes in ONE rollout (one image build, one container recreate per
node, one recorded discontinuity at the window boundary):

1. PR #8: HTTP skin fix (redirect.html), `http.log_redirect_request`,
   normalized manifest hash, `verify-services.py`, `analyze.py --exclude-src`.
2. The enterprise-lure module (`entlure`) with Let's Encrypt TLS on 443.

Everything node-specific (FQDNs, admin CIDRs, window timestamps, LE contact
address) lives in `NOTES.local.md` -- never in tracked files.

## What changes on each node

- Image: rebuilt once on one node, distributed via `docker save`/`docker load`
  (the pinned-image contract from `bootstrap.sh` is unchanged).
- `opencanary.conf`: adds the `entlure.*` section (generic cert paths only).
- `bootstrap.sh`: port 443 moves from counted-only to accepted (`HP_TCP`),
  certbot is installed, `$PREFIX/tls` and the ACME webroot mount are created,
  the generated compose file gains two read mounts.
- nft: 443 stays in `CNT_TCP`, so SYN counting continues unchanged while the
  port now also accepts (same pattern as port 80).

## Phase 0 -- before the window boundary (done, no node changes)

- [x] `entlure` module, skins, Dockerfile install step with import smoke test
- [x] `bin/le-setup.sh`, `bin/coverage-probe.sh`, this document
- [x] Webroot design verified on window 1 (static skin tree serves
      `/.well-known/...` without touching the running module)

## Phase 1 -- at the window boundary (one node at a time, same steps each)

1. Freeze window-1 data and record the boundary timestamp in `NOTES.local.md`.
2. Merge PR #8 and this branch; `git pull` into the node's checkout.
3. **Move any stale `image.tar` in the repo root aside FIRST** (`mv image.tar
   image.tar.window1-bak`): `bootstrap.sh` step 4 auto-loads `image.tar` if
   present and would clobber the freshly built `pinned` tag back to the old
   window-1 image. Then rebuild on the build node:
   `docker build -t honeypot-opencanary:pinned opencanary/`
   (the build FAILS LOUDLY if the entlure import smoke test breaks, and now
   also registers entlure in opencanary.tac — the module is not started
   otherwise). Distribute: `docker save` / `docker load`, record the new
   image ID, and confirm it matches on both nodes.
4. Re-run `bootstrap.sh` on each node with the SAME `NODE_ID` and
   `ADMIN_CIDR` from `NOTES.local.md` (idempotent; regenerates nft, compose,
   mounts).
5. Issue certificates per node:
   `sudo LE_FQDN=<node fqdn> LE_EMAIL=<contact> bin/le-setup.sh`
   Symmetry rule: if issuance fails on ANY node, fix or delay the rollout.
   Window 2 never starts with asymmetric TLS.
6. `docker compose -f /opt/honeypot/docker-compose.yml up -d` (recreate).
7. Verify service answers on BOTH nodes: `bin/verify-services.py <ip-a> <ip-b>`
   -- port lists and banners must be identical.
8. Prove logging coverage on BOTH nodes:
   `bin/coverage-probe.sh <ip> <ssh-target> https`
   -- every probe must produce a log event. "Answers" is not "logs".
9. Record the window-2 start timestamp and the new image ID in
   `NOTES.local.md` and each node's `manifest.txt` refresh (bootstrap step 7).

## Phase 2 -- during window 2

- certbot's timer renews in place; the deploy hook installed by
  `le-setup.sh` refreshes `$PREFIX/tls`.
- The liveness probe (external, hourly) watches service banners AND TLS cert
  validity on 443; a failed renewal alarms before the cert expires.

## Rollback

- The previous pinned image stays on each node. Rollback is:
  `docker tag <old-id> honeypot-opencanary:pinned && docker compose ... up -d`
  plus removing `443` from `HP_TCP` and re-running `bootstrap.sh`.
  Record any rollback in `NOTES.local.md` with a timestamp.

## Design notes (why it is built this way)

- **entlure logs everything, including unknown paths.** The stock http
  module's Error resource answers 404 without logging; on window 1 that made
  path enumeration invisible (live-proven). Coverage is the module's reason
  to exist.
- **Logtypes 50001/50002/50003** (read / write-with-body-sample / probe).
  POST bodies are sampled at 4096 bytes; enough for credential pairs and
  exploit markers, small enough to keep the log lean.
- **TLS via LE on the provider FQDN**: forward-confirmed names, HTTP-01
  through the honeypot's own static tree (no port-80 interruption), renewal
  unattended. Self-signed was rejected: it fingerprints the node and aborts
  strict clients, costing handshake telemetry.
- **No FQDN, address, provider name or contact address in tracked files.**
  `le-setup.sh` refuses to run without `LE_FQDN`/`LE_EMAIL` from the
  environment; AGENTS.md's grep rule is run on every PR.
