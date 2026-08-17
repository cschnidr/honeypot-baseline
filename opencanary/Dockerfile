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

# Deliberately no version pin: the image is built ONCE and distributed to all
# nodes via `docker save` / `docker load`. Identity comes from the tar (image
# ID recorded in each node's manifest.txt), not from the pip pin.
# Resolved versions are in /image-manifest.txt inside the image.

CMD ["opencanaryd", "--dev"]
