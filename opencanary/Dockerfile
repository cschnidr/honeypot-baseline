FROM python:3.12-slim-bookworm

# Build deps only for the C extensions of cryptography/twisted, removed after.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc python3-dev libffi-dev libssl-dev \
 && pip install --no-cache-dir opencanary \
 && pip freeze > /image-manifest.txt \
 && apt-get purge -y gcc python3-dev libffi-dev libssl-dev \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/opencanaryd /var/log/opencanary

# The published opencanary package ships the basicLogin skin WITHOUT
# redirect.html, while RedirectCustomHeaders._get_redirect_file_content() reads
# exactly that file on every request that is answered with a 302. The missing
# file raises FileNotFoundError, Twisted turns it into a 500, and no scanner
# ever reaches the login page - so the HTTP module records neither paths
# (logtype 3000) nor credentials (3001). Verified on image 0a03ecd6: 21 days of
# port-80 traffic produced 24 GET events and zero login attempts on one node.
# The file below is the one the nasLogin skin ships, byte for byte.
# The install path is resolved from the package itself so a Python minor
# version bump does not silently skip the copy.
COPY skin/basicLogin/redirect.html /tmp/redirect.html
RUN python -c "import pathlib, opencanary.modules as m; \
d = pathlib.Path(m.__file__).parent / 'data/http/skin/basicLogin'; \
assert d.is_dir(), d; \
(d / 'redirect.html').write_bytes(pathlib.Path('/tmp/redirect.html').read_bytes())" \
 && rm /tmp/redirect.html

# entlure: enterprise-app lure module (own file, installed into the package).
# Unlike the stock http module it logs EVERY request on its port, including
# unknown paths - the stock module's Error resource answers 404 without
# logging, which made path enumeration invisible (verified live on window 1).
# The import check below is the build-time smoke test: it fails the build if
# the module contract (NAME, getService) ever breaks.
COPY modules/entlure.py /tmp/entlure/entlure.py
COPY skin/entlure /tmp/entlure/skin
RUN python -c "import pathlib, shutil, importlib, opencanary.modules as m; \
root = pathlib.Path(m.__file__).parent; \
shutil.copy('/tmp/entlure/entlure.py', root / 'entlure.py'); \
dst = root / 'data/entlure'; dst.mkdir(parents=True, exist_ok=True); \
[shutil.copy(str(p), dst / p.name) for p in pathlib.Path('/tmp/entlure/skin').iterdir()]; \
mod = importlib.import_module('opencanary.modules.entlure'); \
assert mod.CanaryEntLure.NAME == 'entlure'; \
assert len(mod.LURES) >= 8; \
print('entlure installed with', len(mod.LURES), 'lures')" \
 && rm -rf /tmp/entlure

# Register entlure in opencanary.tac. Dropping the module file into the package
# is NOT enough: opencanaryd starts only the classes in the tac's MODULES list
# (gated by config.moduleEnabled(NAME)); a module that is merely importable and
# has *.enabled=true in the config is never instantiated. Verified live on
# window 2: entlure.py present + entlure.enabled=true, yet port 443 never bound
# because the class was absent from MODULES. This patch adds the import and the
# list entry; `entlure.enabled` in opencanary.conf still gates it on/off.
RUN python -c "import pathlib, shutil; \
bindir = pathlib.Path(shutil.which('opencanaryd')).parent; \
t = bindir / 'opencanary.tac'; \
s = t.read_text(); \
assert 'CanaryMongoDB' in s and 'MODULES = [' in s, 'opencanary.tac layout changed'; \
s = (s.replace('from opencanary.modules.mongodb import CanaryMongoDB', 'from opencanary.modules.mongodb import CanaryMongoDB\nfrom opencanary.modules.entlure import CanaryEntLure', 1) if 'import CanaryEntLure' not in s else s); \
s = (s.replace('MODULES = [\n', 'MODULES = [\n    CanaryEntLure,\n', 1) if 'CanaryEntLure,' not in s else s); \
t.write_text(s); \
assert s.count('CanaryEntLure') >= 2, 'tac registration failed'; \
print('entlure registered in', t)"

# Deliberately no version pin: the image is built ONCE and distributed to all
# nodes via `docker save` / `docker load`. Identity comes from the tar (image
# ID recorded in each node's manifest.txt), not from the pip pin.
# Resolved versions are in /image-manifest.txt inside the image.

CMD ["opencanaryd", "--dev"]
