# reporting — neighbour service image.
#
# Builds FROM the ledger-api image on purpose: Flask and requests are already
# installed there, so this build reuses cached layers and completes in seconds.
# That matters on the constrained dev machine used for this assessment.
#
# In a real estate these would be independent images built from a shared,
# digest-pinned base — chaining app images couples their release cycles and
# means a ledger-api CVE fix silently rebuilds reporting too. Called out in the
# README under known limitations.
FROM ledger-api:0.1.0

# The base image ends on USER 10001, so every RUN here would execute
# unprivileged and groupadd/useradd would fail on the group file lock
# (exit 10). Step up to root for the build steps only, and drop back to a
# non-root UID at the end — the shipped image still runs unprivileged, which
# is what actually matters. Build-time root is not runtime root.
USER root

# Create an unprivileged user. The Kubernetes securityContext also sets
# runAsUser: 10002, but baking it into the image means the container is
# non-root even if someone runs it with plain `docker run` outside the cluster
# — defence in depth rather than relying on the orchestrator alone.
RUN groupadd --gid 10002 reporting \
    && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin reporting

WORKDIR /app
COPY app.py /app/app.py

# Read-only for the running user: the process must never be able to rewrite
# its own code, which is what turns an arbitrary-write bug into persistence.
RUN chown root:root /app/app.py && chmod 0444 /app/app.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10002:10002

EXPOSE 8081

CMD ["python", "app.py"]
