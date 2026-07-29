#!/usr/bin/env bash
#
# Task 3 prerequisite: put the cluster back to the state Tasks 1 and 2 declare.
#
# Task 3 assumes two workloads in `payments`: ledger-api (the PCI-scoped
# service) and reporting (its authorised caller). When this was written the
# cluster had drifted from that:
#
#   - reporting was absent entirely, no Deployment, Service or ConfigMap
#   - ledger-api was running 5 replicas where git declares 2
#
# The replica drift is not an ArgoCD failure. task-2/argocd/application.yaml
# lists /spec/replicas under ignoreDifferences so that ArgoCD and a future HPA
# do not fight over it, which necessarily means ArgoCD will not revert a manual
# scale of that field either. Documented in evidence/00-environment-triage.txt.
#
# Idempotent: safe to re-run.
#
#   ./scripts/restore-baseline.sh
#
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
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T1="$(cd "$HERE/../task-1-workload-hardening" && pwd)"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }

command -v docker  >/dev/null || die "docker not on PATH"
command -v kubectl >/dev/null || die "kubectl not on PATH"
command -v k3d     >/dev/null || die "k3d not on PATH"
docker info >/dev/null 2>&1   || die "Docker daemon is not running"

# k3d publishes the API server on a fresh random host port every time the
# cluster restarts, so the kubeconfig is stale after any restart. Rewrite it
# before doing anything else.
log "Repointing kubeconfig at the current k3d API port"
API_PORT="$(docker port "k3d-${CLUSTER}-serverlb" 6443/tcp | head -1 | sed 's/.*://')"
[ -n "$API_PORT" ] || die "cluster '$CLUSTER' is not running: k3d cluster start $CLUSTER"
kubectl config set-cluster "k3d-${CLUSTER}" --server="https://127.0.0.1:${API_PORT}" >/dev/null
kubectl config use-context "k3d-${CLUSTER}" >/dev/null
echo "    API server: https://127.0.0.1:${API_PORT}"
kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null

# ArgoCD first. With selfHeal:true it would otherwise revert the replica
# reconciliation below while it is still in flight, which makes the result
# non-deterministic and the evidence untrustworthy. Task 2's evidence is
# already captured and committed, so nothing is lost by parking it here.
# scripts/restore-argocd.sh scales it back afterwards.
log "Scaling ArgoCD to zero for the duration of Task 3"
if kubectl get ns argocd >/dev/null 2>&1; then
  kubectl -n argocd scale deploy --all --replicas=0 >/dev/null 2>&1 || true
  kubectl -n argocd scale statefulset --all --replicas=0 >/dev/null 2>&1 || true
  echo "    argocd workloads scaled to 0"
else
  echo "    no argocd namespace, skipping"
fi

# reporting's image is built locally and pushed into the node's containerd by
# `k3d image import`. That is node state, not cluster state: recreating the
# cluster loses it, and the Deployment then sits in ImagePullBackOff forever
# because imagePullPolicy is IfNotPresent and there is no registry to pull from.
log "Checking reporting:0.1.0 is present in the node's image store"
if docker exec "k3d-${CLUSTER}-server-0" crictl images 2>/dev/null \
     | grep -qE '(^|/)reporting[[:space:]]+0\.1\.0'; then
  echo "    present"
else
  warn "not present, rebuilding and importing"

  # OneDrive stores this repo behind reparse points that BuildKit cannot read
  # through ("invalid file request Dockerfile"). Build from a plain temp dir.
  BUILD_TMP="$(mktemp -d)"
  trap 'rm -rf "$BUILD_TMP"' EXIT
  cp "$T1/neighbour-source/app.py" "$T1/neighbour-source/Dockerfile" "$BUILD_TMP/"
  docker build -q -t reporting:0.1.0 "$BUILD_TMP" >/dev/null

  uid="$(docker run --rm --entrypoint sh reporting:0.1.0 -c 'id -u')"
  [ "$uid" != "0" ] || die "reporting:0.1.0 runs as root"
  echo "    rebuilt, uid=$uid"

  k3d image import reporting:0.1.0 -c "$CLUSTER" >/dev/null
  echo "    imported into cluster"
fi

log "Applying ServiceAccounts and the reporting manifest"
kubectl apply -f "$T1/manifests/rbac/00-workload-serviceaccounts.yaml"
kubectl apply -f "$T1/manifests/base/40-reporting.yaml"

log "Reconciling ledger-api to the 2 replicas git declares"
kubectl -n "$NS" scale deploy/ledger-api --replicas=2

log "Waiting for rollouts"
kubectl -n "$NS" rollout status deploy/reporting  --timeout=300s
kubectl -n "$NS" rollout status deploy/ledger-api --timeout=300s

# Prove the two actually talk to each other before any mesh is involved. This
# is the pre-Istio control: every connectivity result captured later in Task 3
# is only meaningful against a baseline that was known-good first.
log "Baseline connectivity check (pre-mesh)"
if kubectl -n "$NS" exec deploy/reporting -c reporting -- \
     python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8081/health',timeout=5).status==200 else 1)" 2>/dev/null; then
  echo "    reporting /health          OK"
else
  warn "reporting /health did not respond"
fi

log "Cluster state"
kubectl -n "$NS" get pods -o wide
echo
echo "Node memory pressure:"
kubectl describe node "k3d-${CLUSTER}-server-0" | sed -n '/Allocated resources/,/^Events/p' | head -10

log "Baseline restored. Next: ./scripts/install-istio.sh"
