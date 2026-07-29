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

# Locate tools rather than requiring them on PATH.
#
# This has to work in two quite different shells:
#
#   Git Bash  - $HOME is /c/Users/<you>, Windows drives are mounted at /c.
#               winget binaries live under AppData/Local/Microsoft/WinGet and
#               Docker Desktop keeps docker/kubectl in its own resources dir;
#               neither is inherited.
#   WSL       - $HOME is /home/<you>, Windows drives are at /mnt/c, and tools
#               are usually installed natively (apt, or a downloaded binary in
#               ~/.local/bin). Docker Desktop's WSL integration provides docker
#               and kubectl on PATH already.
#
# Running `bash script.sh` from PowerShell gets WSL bash, not Git Bash, which
# is why a script that only knew about Git Bash reported tools missing that
# were plainly installed.
#
# Only POSIX paths may be added. A Windows value such as $LOCALAPPDATA cannot:
# PATH is colon-separated, so "C:\Users\me" splits into "C" and "\Users\me" and
# lookups silently resolve to something unexecutable.
_add_path() {
  case "$1" in [A-Za-z]:*) return 0 ;; esac   # refuse Windows-style paths
  [ -d "$1" ] || return 0
  case ":$PATH:" in *":$1:"*) ;; *) PATH="$PATH:$1";; esac
}

_add_path "$HOME/.local/bin"          # WSL: locally installed binaries
_add_path "/usr/local/bin"

# Windows-side locations, reachable from either shell.
for _root in "$HOME/AppData/Local/Microsoft/WinGet" \
             "/mnt/c/Users/${USER:-$(id -un 2>/dev/null)}/AppData/Local/Microsoft/WinGet" \
             "/c/Users/${USER:-$(id -un 2>/dev/null)}/AppData/Local/Microsoft/WinGet"; do
  [ -d "$_root" ] || continue
  _add_path "$_root/Links"
  for _g in "$_root/Packages"/*; do _add_path "$_g"; done
done
for _d in "/c/Program Files/Docker/Docker/resources/bin" \
          "/mnt/c/Program Files/Docker/Docker/resources/bin" \
          "/c/Program Files/GitHub CLI" \
          "/mnt/c/Program Files/GitHub CLI"; do
  _add_path "$_d"
done
export PATH



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
live_image() {
  kubectl get deploy "$APP" -n "$APP_NS" \
    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null
}

RESULT="INCONCLUSIVE"

{
echo "================================================================"
echo " EVIDENCE: ArgoCD drift detection and self-heal"
echo " Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo
echo "The Application sets syncPolicy.automated.selfHeal=true, so git is the"
echo "source of truth and anything else is drift."
echo
echo "NOTE ON WHAT IS DRIFTED, AND WHY IT IS NOT REPLICAS."
echo "An earlier version of this demo scaled the Deployment and reported"
echo "success while nothing was reverted. The Application deliberately sets:"
echo
echo "    ignoreDifferences:"
echo "      - group: apps"
echo "        kind: Deployment"
echo "        jsonPointers: [/spec/replicas]"
echo
echo "so that an autoscaler and ArgoCD do not fight over the replica count."
echo "Replicas are therefore the one field ArgoCD is told to ignore, and"
echo "drifting it proves nothing. This demo changes the container image"
echo "instead: the classic 'someone hotfixed production by hand' change, and"
echo "one ArgoCD very much does watch."
echo

echo "--- 1. Steady state ---"
kubectl get application "$APP" -n "$NS" 2>&1
BEFORE_IMG="$(live_image)"
echo "image in cluster = $BEFORE_IMG"
echo

echo "--- 2. Introduce drift: hand-edit the image, out of band ---"
echo "\$ kubectl set image deploy/$APP ${APP}=nginx:1.27-alpine -n $APP_NS"
kubectl set image deploy/"$APP" "${APP}=nginx:1.27-alpine" -n "$APP_NS" 2>&1
sleep 3
echo "image now = $(live_image)"
echo

echo "--- 3. ArgoCD detects the divergence ---"
# Force an immediate comparison rather than waiting out the 3m poll interval.
kubectl -n "$NS" annotate application "$APP" \
  argocd.argoproj.io/refresh=hard --overwrite >/dev/null 2>&1
DETECTED=0
for i in $(seq 1 30); do
  s="$(status)"
  echo "  t+${i}s  $s"
  case "$s" in *OutOfSync*) echo "  -> DRIFT DETECTED"; DETECTED=1; break;; esac
  sleep 2
done
[ "$DETECTED" -eq 1 ] || echo "  -> no OutOfSync seen (it may have self-healed before the first poll)"
echo

echo "--- 4. Self-heal reverts it, with no human action ---"
HEALED=0
for i in $(seq 1 45); do
  cur="$(live_image)"
  echo "  t+$((i*2))s  image=$cur  $(status)"
  if [ "$cur" = "$BEFORE_IMG" ]; then
    echo "  -> SELF-HEALED: image is back to the digest declared in git"
    HEALED=1
    break
  fi
  sleep 2
done
echo

echo "--- 5. Final state ---"
kubectl get application "$APP" -n "$NS" 2>&1
echo "image in cluster = $(live_image)"
echo "image declared in git ="
grep -m1 -E '^[[:space:]]+image: ghcr' "$HERE/gitops/ledger-api-deployment.yaml" 2>/dev/null | sed 's/^ */  /'
echo

# Report what actually happened. The previous version printed a success line
# unconditionally, which is worse than no evidence at all: it asserted a
# control was working while the transcript above showed it had not fired.
if [ "$HEALED" -eq 1 ]; then
  RESULT="PASS"
  echo "RESULT: PASS. The hand-made change was detected and reverted"
  echo "automatically. Drift was transient and logged rather than permanent"
  echo "and invisible, and git stayed the source of truth."
else
  RESULT="FAIL"
  echo "RESULT: FAIL. The image was still $(live_image) after 90s, so"
  echo "self-heal did not revert it. Check that syncPolicy.automated.selfHeal"
  echo "is true and that this field is not covered by ignoreDifferences."
fi
} 2>&1 | tee "$OUT"

log "Saved to $OUT"
[ "$RESULT" = "PASS" ] || exit 1
