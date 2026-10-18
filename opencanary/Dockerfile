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

# Deliberately no version pin: the image is built ONCE and distributed to all
# nodes via `docker save` / `docker load`. Identity comes from the tar (image
# ID recorded in each node's manifest.txt), not from the pip pin.
# Resolved versions are in /image-manifest.txt inside the image.

CMD ["opencanaryd", "--dev"]
