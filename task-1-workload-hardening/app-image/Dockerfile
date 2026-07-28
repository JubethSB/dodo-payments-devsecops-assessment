# ledger-api — hardened image.
#
# Replaces app-source/app/Dockerfile. What changed and why:
#
#   1. Multi-stage build. pip and its build toolchain stay in the builder
#      stage, so the shipped image has no compiler and no package manager for
#      an attacker to use to pull down tooling after landing RCE.
#   2. A real non-root user baked into the image (uid 10001). The Kubernetes
#      securityContext also enforces runAsNonRoot, but an image that is
#      non-root on its own stays non-root under plain `docker run`, in another
#      orchestrator, or if the manifest is ever misapplied.
#   3. Application code owned by root and mode 0444 — the running user cannot
#      rewrite its own source, which is what blocks arbitrary-write bugs from
#      becoming persistence.
#   4. No shell history, no cache, no pip metadata left behind.
#
# KNOWN AND DELIBERATE: the base is python:3.6-slim and the dependencies are
# the starter's pinned (old) versions. They are NOT upgraded here, for two
# reasons. First, Flask 0.12.2 / PyYAML 5.1 do not run on a modern interpreter,
# so upgrading the base means rewriting the app. Second, the application-level
# vulnerabilities in app.py (yaml.load deserialisation on /import, SSRF on
# /fetch, cleartext PANs on /transactions) are the authorised target for
# Task 4 — patching them here would delete the thing the pen test exists to
# find. Task 2's Trivy/Grype gate is expected to flag this base image and these
# dependencies, and that finding firing is the demonstration that the gate
# works. Remediation path is documented in the Task 1 README.

# ---------- builder ----------
FROM python:3.6-slim AS builder

WORKDIR /build

COPY requirements.txt .

# --prefix keeps everything under one tree we can copy wholesale into the
# runtime stage without dragging pip along with it.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- runtime ----------
FROM python:3.6-slim AS runtime

# Non-root identity. --no-create-home and nologin: this account exists only to
# own a process, it is not something anyone should be able to log in as.
RUN groupadd --gid 10001 ledger \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin ledger

# Installed dependencies from the builder — no pip, no wheels, no build cache.
COPY --from=builder /install /usr/local

WORKDIR /app
COPY app.py /app/app.py

# Code is root-owned and read-only to everyone, including the user that runs it.
RUN chown root:root /app/app.py && chmod 0444 /app/app.py

# PYTHONDONTWRITEBYTECODE is required, not cosmetic: the container runs with a
# read-only root filesystem, so an interpreter trying to write .pyc files next
# to the source errors on every import.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001

EXPOSE 8080

CMD ["python", "app.py"]
