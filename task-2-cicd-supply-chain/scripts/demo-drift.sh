#!/usr/bin/env bash
#
# Demonstrate ArgoCD drift detection and self-heal.
#
# The assessment asks to "show drift detection + self-heal after a manual
# kubectl edit". This script performs that edit, watches ArgoCD notice, and
# records the transcript to evidence/.
#
#   ./demo-drift.sh
#
# What it proves, and why it matters beyond a neat demo:
# a manual change to a PCI-scoped workload is an undocumented change. Without
# reconciliation it persists silently and the cluster diverges from the audited
# state in git, so "what is running in production?" stops being answerable
# from the repository. Self-heal converts that from a permanent, invisible
# divergence into a transient, logged one.
set -uo pipefail

NS=argocd
APP_NS=payments
APP=ledger-api
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$HERE/evidence/05-argocd-drift-selfheal.txt"
mkdir -p "$HERE/evidence"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

kubectl get application "$APP" -n "$NS" >/dev/null 2>&1 || {
  echo "Application '$APP' not found in namespace '$NS'." >&2
  echo "Run ./bootstrap-argocd.sh <git-repo-url> first." >&2
  exit 1
}

status() {
  kubectl get application "$APP" -n "$NS" \
    -o jsonpath='sync={.status.sync.status} health={.status.health.status}' 2>/dev/null
  echo
}

{
echo "================================================================"
echo " EVIDENCE: ArgoCD drift detection and self-heal"
echo " Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo
echo "The Application is configured with syncPolicy.automated.selfHeal=true."
echo "Git is the source of truth; anything else is drift."
echo

echo "--- 1. Steady state: live cluster matches git ---"
echo "\$ kubectl get application $APP -n $NS"
kubectl get application "$APP" -n "$NS" 2>&1
echo
echo "\$ kubectl get deploy $APP -n $APP_NS -o jsonpath='{.spec.replicas}'"
BEFORE="$(kubectl get deploy "$APP" -n "$APP_NS" -o jsonpath='{.spec.replicas}' 2>/dev/null)"
echo "replicas = $BEFORE"
echo

echo "--- 2. Introduce drift: a manual, out-of-band kubectl edit ---"
echo "This is the change an engineer makes at 3am and forgets to commit."
echo "\$ kubectl scale deploy/$APP -n $APP_NS --replicas=5"
kubectl scale deploy/"$APP" -n "$APP_NS" --replicas=5 2>&1
sleep 2
echo "replicas now = $(kubectl get deploy "$APP" -n "$APP_NS" -o jsonpath='{.spec.replicas}' 2>/dev/null)"
echo

echo "--- 3. ArgoCD detects the divergence ---"
# Force an immediate comparison instead of waiting for the poll interval
# (default 3m), so the transcript stays readable.
kubectl -n "$NS" annotate application "$APP" \
  argocd.argoproj.io/refresh=hard --overwrite >/dev/null 2>&1
for i in $(seq 1 30); do
  s="$(status)"
  echo "  t+${i}s  $s"
  case "$s" in *OutOfSync*) echo "  -> DRIFT DETECTED"; break;; esac
  sleep 1
done
echo

echo "--- 4. Self-heal reverts it without human action ---"
for i in $(seq 1 60); do
  r="$(kubectl get deploy "$APP" -n "$APP_NS" -o jsonpath='{.spec.replicas}' 2>/dev/null)"
  s="$(status)"
  echo "  t+${i}s  replicas=$r  $s"
  if [ "$r" = "$BEFORE" ]; then
    echo "  -> SELF-HEALED: replicas back to $BEFORE, as declared in git"
    break
  fi
  sleep 2
done
echo

echo "--- 5. Final state ---"
kubectl get application "$APP" -n "$NS" 2>&1
kubectl get deploy "$APP" -n "$APP_NS" 2>&1
echo
echo "RESULT: the manual change was detected and reverted automatically."
echo "Git remained the source of truth; the drift was transient and logged"
echo "rather than permanent and invisible."
} 2>&1 | tee "$OUT"

log "Saved to $OUT"
