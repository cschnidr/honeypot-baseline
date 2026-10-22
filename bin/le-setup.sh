#!/usr/bin/env bash
# le-setup.sh -- issue (or renew) this node's Let's Encrypt certificate for
# the entlure TLS port, via HTTP-01 through the honeypot's own static web
# tree. No downtime, no extra listener: the running http module serves the
# challenge from $PREFIX/le-webroot, which bootstrap.sh mounts into the
# container's static skin path.
#
# Required environment (keep the values in NOTES.local.md, never in git):
#   LE_FQDN   this node's provider-assigned hostname (must forward-resolve
#             to this node's public IP; verify: dig +short A "$LE_FQDN")
#   LE_EMAIL  contact address for the Let's Encrypt account
# Optional:
#   LE_STAGING=1  use the LE staging environment (test runs, no rate limits)
#
# Run per node, AFTER bootstrap.sh and the container are up:
#   sudo LE_FQDN=<node fqdn> LE_EMAIL=<address> bin/le-setup.sh
#
# Renewal: certbot's own systemd timer renews in place; the deploy hook this
# script installs copies the fresh cert into $PREFIX/tls, where the entlure
# module reads it (paths are generic, the FQDN appears only in LE's own
# host-local directories).
set -euo pipefail

: "${LE_FQDN:?set LE_FQDN, the provider-assigned hostname of this node}"
: "${LE_EMAIL:?set LE_EMAIL, the ACME contact address for this node}"
PREFIX="${PREFIX:-/opt/honeypot}"
WEBROOT="$PREFIX/le-webroot"
TLSOUT="$PREFIX/tls"
STAGING=()
[[ "${LE_STAGING:-0}" == "1" ]] && STAGING=(--staging)

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
command -v certbot >/dev/null || { echo "certbot missing (bootstrap.sh installs it)" >&2; exit 1; }
mkdir -p "$WEBROOT/.well-known" "$TLSOUT"

# Pre-flight 1: the FQDN must forward-resolve to THIS node, or HTTP-01 fails.
# Vars are pre-initialised and the pipelines carry `|| true`, so a transient
# `ip`/`getent` failure under `set -euo pipefail` can neither abort the script
# nor leave a var unbound (an unbound MY_IP aborting here was observed once).
# `src` is extracted by name, not column position, so the `ip` output layout
# cannot shift it.
MY_IP=""
MY_IP="$(ip -o route get 1 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -1)" || true
FQDN_IP=""
FQDN_IP="$(getent ahostsv4 "$LE_FQDN" 2>/dev/null | awk 'NR==1{print $1}')" || true
[[ -n "$FQDN_IP" ]] || { echo "$LE_FQDN does not resolve" >&2; exit 1; }
[[ -n "$MY_IP" && "$FQDN_IP" == "$MY_IP" ]] || \
  echo "WARNING: $LE_FQDN -> ${FQDN_IP:-?}, this node -> ${MY_IP:-unknown} (continuing anyway)" >&2

# Pre-flight 2: prove the webroot is served through the honeypot, so a failed
# issuance never burns the 5/week rate limit on a path problem.
MARKER="le-preflight-$(date +%s)-$$"
echo ok > "$WEBROOT/.well-known/$MARKER"
CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  "http://$LE_FQDN/.well-known/$MARKER")"
rm -f "$WEBROOT/.well-known/$MARKER"
[[ "$CODE" == "200" ]] || {
  echo "webroot not reachable: http://$LE_FQDN/.well-known/$MARKER -> HTTP $CODE" >&2
  echo "check: container up? bootstrap mount present? port 80 open?" >&2
  exit 1
}

# Deploy hook FIRST, so every renewal (not just this run) refreshes the
# entlure-readable copy. Lives only on the host; the FQDN never enters git.
# certbot creates this tree on first run, but we write the hook before that
# first run, so ensure it exists.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/honeypot-entlure.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
install -m 0644 "/etc/letsencrypt/live/$LE_FQDN/fullchain.pem" "$TLSOUT/fullchain.pem"
install -m 0600 "/etc/letsencrypt/live/$LE_FQDN/privkey.pem"   "$TLSOUT/privkey.pem"
# entlure holds the cert in memory; restart so issuance AND renewals go live.
docker compose -f "$PREFIX/docker-compose.yml" restart
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/honeypot-entlure.sh

certbot certonly --non-interactive --agree-tos --email "$LE_EMAIL" \
  "${STAGING[@]}" --webroot -w "$WEBROOT" -d "$LE_FQDN"

/etc/letsencrypt/renewal-hooks/deploy/honeypot-entlure.sh

echo "certificate installed: $TLSOUT/fullchain.pem (+ privkey.pem)"
echo "entlure reads it at container start; restart the container if it is already running:"
echo "  docker compose -f $PREFIX/docker-compose.yml restart"
