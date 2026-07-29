#!/usr/bin/env bash
#
# Un-park ArgoCD after Task 3.
#
# restore-baseline.sh scales ArgoCD to zero so that selfHeal does not fight the
# workload changes Task 3 makes, and so that its ~300-400 MB is available to
# istiod and the sidecars on a 3.47 GiB node. This script puts it back.
#
#   ./scripts/restore-argocd.sh
#
# It restores the replica counts RECORDED AT PARK TIME, not a hardcoded 1.
# That distinction matters: several ArgoCD components were already at 0 replicas
# before Task 3 began (applicationset-controller, dex-server,
# notifications-controller, scaled down to fit this node). Setting everything to
# 1 would not restore the cluster, it would silently change it and quietly
# consume memory nobody asked for.
#
# Run this before demonstrating anything from Task 2 again. Leaving ArgoCD at
# zero means GitOps drift detection and self-heal are OFF, and a Task 2 demo run
# in that state would appear to work while proving nothing.
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
STATE_CM=argocd-prescale-state

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

kubectl get ns argocd >/dev/null 2>&1 || die "no argocd namespace on this cluster"

log "Reading the recorded pre-scale state"
if ! kubectl -n argocd get configmap "$STATE_CM" >/dev/null 2>&1; then
  warn "ConfigMap argocd/$STATE_CM not found."
  warn "Either ArgoCD was never parked by restore-baseline.sh, or the ConfigMap"
  warn "was deleted. Nothing can be restored safely without knowing the original"
  warn "replica counts - guessing would change the cluster rather than restore it."
  warn ""
  warn "If you are certain, scale the core components manually:"
  warn "  kubectl -n argocd scale statefulset/argocd-application-controller --replicas=1"
  warn "  kubectl -n argocd scale deploy/argocd-repo-server deploy/argocd-server \\"
  warn "                            deploy/argocd-redis --replicas=1"
  exit 1
fi

STATE="$(kubectl -n argocd get configmap "$STATE_CM" -o jsonpath='{.data.replicas}')"
[ -n "$STATE" ] || die "$STATE_CM exists but records no replica data"
echo "$STATE" | sed '/^$/d; s/^/    /'

log "Restoring replica counts"
RESTORED=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  target="${line%%=*}"     # e.g. deployment/argocd-server
  replicas="${line##*=}"

  # A component recorded at 0 was already off before Task 3. Leave it off.
  if [ "$replicas" = "0" ] || [ -z "$replicas" ]; then
    echo "    skip    $target (was already 0 before Task 3)"
    continue
  fi

  if kubectl -n argocd get "$target" >/dev/null 2>&1; then
    kubectl -n argocd scale "$target" --replicas="$replicas" >/dev/null
    echo "    scaled  $target -> $replicas"
    RESTORED=$((RESTORED+1))
  else
    warn "$target no longer exists, skipping"
  fi
done <<< "$STATE"

# Every recorded count was 0, so there is nothing to scale up. Fail loudly
# rather than printing a success message over a no-op.
#
# Seen for real: if ArgoCD was already parked by hand BEFORE restore-baseline.sh
# first recorded state, the snapshot captures all-zeros and faithfully restoring
# it does nothing. The recording is working correctly; it recorded an
# already-parked cluster. Recovery is to write the true pre-Task-3 counts into
# the ConfigMap and re-run.
if [ "$RESTORED" -eq 0 ]; then
  warn "Every recorded replica count was 0, so nothing was restored."
  warn ""
  warn "This usually means ArgoCD was already scaled to zero before"
  warn "restore-baseline.sh first recorded state, so the snapshot captured an"
  warn "already-parked cluster rather than a running one."
  warn ""
  warn "Fix by recording the true pre-Task-3 counts, then re-running:"
  warn "  kubectl -n argocd create configmap $STATE_CM --from-literal=replicas=\\"
  warn "'deployment/argocd-redis=1"
  warn "deployment/argocd-repo-server=1"
  warn "deployment/argocd-server=1"
  warn "statefulset/argocd-application-controller=1' \\"
  warn "    --dry-run=client -o yaml | kubectl apply -f -"
  die "refusing to report success over a no-op restore"
fi

log "Waiting for ArgoCD to become ready"
# Non-fatal: on a memory-constrained node ArgoCD can take a long time or fail to
# schedule alongside Istio. That is worth reporting honestly rather than hiding
# behind a failed exit code.
kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s || \
  warn "application-controller did not become ready in time"
for d in argocd-repo-server argocd-server argocd-redis; do
  kubectl -n argocd get deploy "$d" >/dev/null 2>&1 || continue
  kubectl -n argocd rollout status "deploy/$d" --timeout=300s || warn "$d did not become ready in time"
done

log "ArgoCD state"
kubectl -n argocd get pods

# The point of restoring ArgoCD is that GitOps reconciliation resumes. Say so
# explicitly rather than leaving the operator to assume it from pod status.
log "Application sync status"
if kubectl -n argocd get application ledger-api >/dev/null 2>&1; then
  kubectl -n argocd get application ledger-api \
    -o custom-columns='NAME:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status'
  echo
  echo "  Note: Task 3 changed workloads that this Application manages, so an"
  echo "  OutOfSync result here is expected and correct. With selfHeal:true it"
  echo "  will reconcile back to git on its own - which will REMOVE the Istio"
  echo "  sidecar annotations if they are not committed to the GitOps path."
else
  warn "no ledger-api Application found"
fi

# Clean up the state record only after a successful restore, so a failed run can
# be retried against the same data.
kubectl -n argocd delete configmap "$STATE_CM" >/dev/null 2>&1 || true

log "ArgoCD restored."
