#!/usr/bin/env bash
#
# Task 3, milestone 1: install Istio and bring payments into the mesh.
#
#   ./scripts/install-istio.sh              # install and inject
#   ISTIO_VERSION=1.27.1 ./scripts/install-istio.sh
#
# Prerequisite: ./scripts/restore-baseline.sh
#
# This script refuses to install if the k3s CNI paths do not match what
# istio/00-istio-install.yaml declares. That check exists because the failure
# it prevents is genuinely nasty: a CNI DaemonSet pointed at the wrong
# directory starts healthy, reports Ready, and silently redirects nothing. The
# symptom is that mTLS "does not work", which sends you debugging
# PeerAuthentication instead of the install.
set -euo pipefail

_add_path() {
  case "$1" in [A-Za-z]:*) return 0 ;; esac
  [ -d "$1" ] || return 0
  case ":$PATH:" in *":$1:"*) ;; *) PATH="$PATH:$1";; esac
}
_add_path "$HOME/.local/bin"
_add_path "/usr/local/bin"
export PATH

CLUSTER=ledger
NS=payments
NODE="k3d-${CLUSTER}-server-0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HOME/.local/bin"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }

command -v docker  >/dev/null || die "docker not on PATH"
command -v kubectl >/dev/null || die "kubectl not on PATH"
docker info >/dev/null 2>&1   || die "Docker daemon is not running"

log "Repointing kubeconfig at the current k3d API port"
API_PORT="$(docker port "k3d-${CLUSTER}-serverlb" 6443/tcp | head -1 | sed 's/.*://')"
[ -n "$API_PORT" ] || die "cluster '$CLUSTER' is not running"
kubectl config set-cluster "k3d-${CLUSTER}" --server="https://127.0.0.1:${API_PORT}" >/dev/null
kubectl config use-context "k3d-${CLUSTER}" >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null
echo "    https://127.0.0.1:${API_PORT}"

# ---------------------------------------------------------------------------
# 1. istioctl
# ---------------------------------------------------------------------------
log "Resolving istioctl"
if [ -z "${ISTIO_VERSION:-}" ]; then
  ISTIO_VERSION="$(curl -fsSL https://api.github.com/repos/istio/istio/releases/latest \
                   | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$ISTIO_VERSION" ] || die "could not resolve the latest Istio release; set ISTIO_VERSION"
fi
echo "    version: $ISTIO_VERSION"

if command -v istioctl >/dev/null 2>&1 && \
   [ "$(istioctl version --remote=false 2>/dev/null)" = "$ISTIO_VERSION" ]; then
  echo "    istioctl $ISTIO_VERSION already installed"
else
  mkdir -p "$BIN"
  TARBALL="istioctl-${ISTIO_VERSION}-linux-amd64.tar.gz"
  URL="https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/${TARBALL}"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  echo "    downloading $URL"
  curl -fsSL "$URL" -o "$TMP/$TARBALL" || die "download failed"
  tar -xzf "$TMP/$TARBALL" -C "$TMP"
  install -m 0755 "$TMP/istioctl" "$BIN/istioctl"
  echo "    installed to $BIN/istioctl"
fi
istioctl version --remote=false

# ---------------------------------------------------------------------------
# 2. Verify the CNI paths the operator config assumes
# ---------------------------------------------------------------------------
log "Verifying k3s CNI paths before installing"
DECLARED_CONF="$(sed -n 's/^ *cniConfDir: *//p' "$HERE/istio/00-istio-install.yaml" | head -1)"
DECLARED_BIN="$(sed -n 's/^ *cniBinDir: *//p'  "$HERE/istio/00-istio-install.yaml" | head -1)"
echo "    declared cniConfDir: $DECLARED_CONF"
echo "    declared cniBinDir:  $DECLARED_BIN"

docker exec "$NODE" test -d "$DECLARED_CONF" \
  || die "cniConfDir '$DECLARED_CONF' does not exist on $NODE. Inspect with:
    docker exec $NODE find / -name '*.conflist' -path '*cni*' 2>/dev/null"

# Verify against the directory KUBELET loads plugins from, not merely a
# directory that happens to contain some.
#
# This distinction is the whole point. /bin on a k3s node contains portmap,
# bridge and loopback, so a "does this dir have CNI plugins?" check passes on
# it - and it is still the wrong answer, because kubelet reads
# /var/lib/rancher/k3s/data/cni. Installing istio-cni to the wrong directory
# yields a healthy-looking DaemonSet and pods that can never get a sandbox:
#
#   failed to find plugin "istio-cni" in path [/var/lib/rancher/k3s/data/cni]
#
# Resolve the authoritative path from the running kubelet's own flags, and fall
# back to probing only if that is unavailable.
KUBELET_BIN_DIR="$(docker exec "$NODE" sh -c \
  "cat /proc/\$(pgrep -f 'kubelet' | head -1)/cmdline 2>/dev/null | tr '\0' '\n' | sed -n 's/^--cni-bin-dir=//p'" 2>/dev/null | head -1)"

if [ -z "$KUBELET_BIN_DIR" ]; then
  # k3s embeds kubelet, so the flag may not be visible. Probe the known k3s
  # location before the upstream default.
  for d in /var/lib/rancher/k3s/data/cni /opt/cni/bin /bin; do
    if docker exec "$NODE" sh -c "ls '$d' 2>/dev/null | grep -qE '^(portmap|bridge|loopback|host-local)$'"; then
      KUBELET_BIN_DIR="$d"; break
    fi
  done
fi
echo "    kubelet loads plugins from: ${KUBELET_BIN_DIR:-<unknown>}"

if [ -n "$KUBELET_BIN_DIR" ] && [ "$KUBELET_BIN_DIR" != "$DECLARED_BIN" ]; then
  warn "cniBinDir mismatch."
  warn "  declared: $DECLARED_BIN"
  warn "  kubelet:  $KUBELET_BIN_DIR"
  warn "istio-cni would install where kubelet never looks. Every pod sandbox"
  warn "would then fail with 'failed to find plugin istio-cni in path ...',"
  warn "while the CNI DaemonSet still reports Running and Ready."
  die "set cniBinDir: $KUBELET_BIN_DIR in istio/00-istio-install.yaml"
fi
docker exec "$NODE" test -d "$DECLARED_BIN" \
  || die "cniBinDir '$DECLARED_BIN' does not exist on $NODE"
echo "    cniBinDir agrees with kubelet  OK"
docker exec "$NODE" ls "$DECLARED_CONF" | sed 's/^/      /'

# ---------------------------------------------------------------------------
# 3. Install
# ---------------------------------------------------------------------------
log "Validating the IstioOperator manifest"
istioctl validate -f "$HERE/istio/00-istio-install.yaml" && echo "    valid"

log "Installing Istio (this takes a few minutes on a small node)"
istioctl install -f "$HERE/istio/00-istio-install.yaml" --skip-confirmation

log "Waiting for the control plane"
kubectl -n istio-system rollout status deploy/istiod --timeout=420s
kubectl -n istio-system rollout status daemonset/istio-cni-node --timeout=300s

log "Control plane state"
kubectl -n istio-system get pods -o wide

# ---------------------------------------------------------------------------
# 4. Bring payments into the mesh
# ---------------------------------------------------------------------------
log "Labelling $NS for sidecar injection"
kubectl label namespace "$NS" istio-injection=enabled --overwrite

log "Restarting workloads so they pick up a sidecar"
kubectl -n "$NS" rollout restart deploy/ledger-api deploy/reporting
kubectl -n "$NS" rollout status  deploy/ledger-api --timeout=420s
kubectl -n "$NS" rollout status  deploy/reporting  --timeout=420s

# ---------------------------------------------------------------------------
# 5. Prove the hardening survived
# ---------------------------------------------------------------------------
log "Confirming sidecars were injected AND the Task 1 controls still hold"
kubectl -n "$NS" get pods -o custom-columns=\
'POD:.metadata.name,READY:.status.containerStatuses[*].ready,CONTAINERS:.spec.containers[*].name'

echo
echo "  Namespace still enforcing PSS restricted:"
kubectl get ns "$NS" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}' \
  | sed 's/^/    enforce=/'

echo
echo "  No pod carries NET_ADMIN or NET_RAW (istio-cni did the iptables work):"
if kubectl -n "$NS" get pods -o json \
     | grep -qE '"(NET_ADMIN|NET_RAW)"'; then
  warn "a pod requests NET_ADMIN/NET_RAW - istio-cni is NOT in effect"
else
  echo "    confirmed, no elevated capabilities in $NS"
fi

echo
echo "  Sidecar securityContext (must satisfy Task 1's Kyverno policies):"
kubectl -n "$NS" get pod -l app.kubernetes.io/name=ledger-api -o \
  jsonpath='{range .items[0].spec.containers[?(@.name=="istio-proxy")]}    runAsUser={.securityContext.runAsUser} readOnlyRootFs={.securityContext.readOnlyRootFilesystem} allowPrivEsc={.securityContext.allowPrivilegeEscalation} drop={.securityContext.capabilities.drop}{"\n"}    requests={.resources.requests} limits={.resources.limits}{"\n"}{end}'

echo
echo "  Kyverno verdict on the injected pods:"
kubectl -n "$NS" get events --field-selector reason=PolicyViolation 2>/dev/null | tail -5 \
  || echo "    no PolicyViolation events"

log "Mesh established. Next: ./scripts/verify-mtls.sh"
