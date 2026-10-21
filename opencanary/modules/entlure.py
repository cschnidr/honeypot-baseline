# entlure.py -- enterprise-app lures with full request coverage.
#
# Why this module exists: the stock http.py module only logs requests that
# reach its skin login page; every other path is answered 404 by an Error
# resource WITHOUT logging, so path enumeration (the dominant behaviour of
# web exploit scanners) is invisible to it. Verified empirically against a
# live node: a GET to an unknown path produced a 404 and zero log events.
#
# This module takes the opposite approach: EVERY request to the port is
# logged -- lure hits, probes, unknown paths, every method. Lures return
# small plausible static bodies; logging coverage never depends on which
# path was requested.
#
# Lure set (window-2 experiment, enterprise attack surface):
#   - Metabase    (pre-auth RCE / exposure scanning patterns)
#   - Exchange    (OWA/ECP/autodiscover credential and exploit probes)
#   - SharePoint  (/_layouts/15/ toolpane/start probes)
#   - VPN portal  (GlobalProtect-style login probe)
#   - WordPress   (PHP-app probes: wp-login credential stuffing, xmlrpc
#                  brute-force amplification, generic index.php probes --
#                  the paths PHP-CVE exploitation waves hunt)
#
# Logtypes (own range, see bin/analyze.py output "event types"):
#   50001  GET/HEAD/OPTIONS against a known lure path
#   50002  POST/PUT/PATCH/DELETE against a known lure path (body sample logged)
#   50003  any request to an unknown path (probe coverage, body sample logged)
#
# Config keys:
#   entlure.enabled          bool
#   entlure.port             int (default 443)
#   entlure.tls.enabled      bool (default false)
#   entlure.tls.certificate  path to fullchain PEM (default /etc/opencanaryd/tls/fullchain.pem)
#   entlure.tls.key          path to privkey PEM   (default /etc/opencanaryd/tls/privkey.pem)
#   entlure.banner           Server header (default "Microsoft-IIS/10.0")

import os

from twisted.application import internet
from twisted.web import resource, server

from opencanary.modules import CanaryService

LOG_LURE_READ = 50001
LOG_LURE_WRITE = 50002
LOG_PROBE = 50003

MAX_BODY_SAMPLE = 4096

# path (relative, no leading slash) -> (app name, body file, content type, http status)
# Body files live in the package's data/entlure/ directory, installed by the
# image build from opencanary/skin/entlure/ in this repository.
LURES = {
    "api/session/properties": ("metabase", "metabase-properties.json", b"application/json", 200),
    "api/setup/validate": ("metabase", "metabase-validate.json", b"application/json", 400),
    "owa/auth/logon.aspx": ("exchange", "owa-logon.html", b"text/html; charset=utf-8", 200),
    "ecp/": ("exchange", "owa-logon.html", b"text/html; charset=utf-8", 200),
    "autodiscover/autodiscover.xml": ("exchange", "autodiscover.xml", b"text/xml", 401),
    "_layouts/15/start.aspx": ("sharepoint", "sharepoint.html", b"text/html; charset=utf-8", 200),
    "_layouts/15/toolpane.aspx": ("sharepoint", "sharepoint.html", b"text/html; charset=utf-8", 200),
    "global-protect/login.esp": ("gpvpn", "gp-login.html", b"text/html; charset=utf-8", 200),
    # PHP-app surface: WordPress is the most-probed PHP target class on the
    # internet (credential stuffing on wp-login, brute-force amplification on
    # xmlrpc, generic app probes on index.php). PHP-CVE exploitation waves
    # hunt exactly these paths.
    "wp-login.php": ("wordpress", "wp-login.html", b"text/html; charset=utf-8", 200),
    "xmlrpc.php": ("wordpress", "xmlrpc.txt", b"text/plain; charset=utf-8", 200),
    "index.php": ("wordpress", "wp-index.html", b"text/html; charset=utf-8", 200),
}

WRITE_METHODS = (b"POST", b"PUT", b"PATCH", b"DELETE")


def _text(raw):
    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)


class EntLureRoot(resource.Resource):
    """Single isLeaf resource: sees and logs EVERY request, no silent 404s."""

    isLeaf = True

    def __init__(self, factory):
        resource.Resource.__init__(self)
        self.factory = factory

    def _log_request(self, request, app, is_write):
        logtype = LOG_PROBE
        if app is not None:
            logtype = LOG_LURE_WRITE if is_write else LOG_LURE_READ
        logdata = {
            "APP": app or "NONE",
            "METHOD": _text(request.method),
            "PATH": _text(request.path),
            "HOSTNAME": _text(request.getRequestHostname()),
            "USERAGENT": _text(request.getHeader(b"user-agent") or b"<not supplied>"),
        }
        if is_write and request.content is not None:
            body = request.content.read(MAX_BODY_SAMPLE)
            logdata["BODY"] = _text(body)
            logdata["BODY_TRUNCATED"] = len(body) == MAX_BODY_SAMPLE
        self.factory.log(logdata, transport=request.transport, logtype=logtype)

    def render(self, request):
        request.setHeader(b"Server", self.factory.banner)
        is_write = request.method in WRITE_METHODS
        rel = _text(request.path).lstrip("/")
        lure = LURES.get(rel) or LURES.get(rel.lower())
        self._log_request(request, lure[0] if lure else None, is_write)
        if lure is None:
            request.setResponseCode(404)
            request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
            return self.factory.notfound_body
        _, body, content_type, status = lure
        request.setResponseCode(status)
        request.setHeader(b"Content-Type", content_type)
        return self.factory.bodies[body]


class CanaryEntLure(CanaryService):
    NAME = "entlure"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("entlure.port", default=443))
        self.use_tls = bool(config.getVal("entlure.tls.enabled", default=False))
        self.cert = config.getVal(
            "entlure.tls.certificate", default="/etc/opencanaryd/tls/fullchain.pem"
        )
        self.key = config.getVal(
            "entlure.tls.key", default="/etc/opencanaryd/tls/privkey.pem"
        )
        ubanner = config.getVal("entlure.banner", default="Microsoft-IIS/10.0")
        self.banner = ubanner.encode("utf8")
        self.listen_addr = config.getVal("device.listen_addr", default="")
        datadir = os.path.join(self.resource_dir())
        self.bodies = {}
        for _, (_, fname, _, _) in LURES.items():
            if fname in self.bodies:
                continue
            with open(os.path.join(datadir, fname), "rb") as fh:
                self.bodies[fname] = fh.read()
        self.notfound_body = b"<html><body><h1>404 Not Found</h1></body></html>"

    def _cert_paths(self):
        """Resolve the TLS cert/key pair, never crashing on missing files.

        Rollout sequence depends on this: the container must come up BEFORE
        le-setup.sh can issue the first certificate, so at first boot the
        configured paths do not exist yet. Same fallback pattern as the stock
        https module: generate a self-signed pair into a container-local
        path and serve that until le-setup installs the real one and the
        container restarts.
        """
        if os.path.exists(self.cert) and os.path.exists(self.key):
            return self.cert, self.key
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        fb_dir = "/etc/ssl/opencanary"
        os.makedirs(fb_dir, exist_ok=True)
        fb_cert = os.path.join(fb_dir, "entlure-fallback.pem")
        fb_key = os.path.join(fb_dir, "entlure-fallback.key")
        if not (os.path.exists(fb_cert) and os.path.exists(fb_key)):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(fb_key, "wb") as fh:
                fh.write(
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    )
                )
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.datetime.utcnow()
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .sign(key, hashes.SHA256())
            )
            with open(fb_cert, "wb") as fh:
                fh.write(cert.public_bytes(serialization.Encoding.PEM))
        return fb_cert, fb_key

    def getService(self):
        site = server.Site(EntLureRoot(self))
        if self.use_tls:
            from twisted.internet.ssl import DefaultOpenSSLContextFactory

            cert, key = self._cert_paths()
            context = DefaultOpenSSLContextFactory(key, cert)
            return internet.SSLServer(
                self.port, site, context, interface=self.listen_addr
            )
        return internet.TCPServer(self.port, site, interface=self.listen_addr)
