#!/usr/bin/env bash
#
# Install ArgoCD into the local cluster and register the ledger-api Application.
#
#   ./bootstrap-argocd.sh https://github.com/<you>/<repo>.git
#
# Requires the Task 1 cluster (namespace `payments`, ServiceAccount, and the
# SealedSecret) to exist already, see task-1-workload-hardening/scripts/deploy.sh.
#
# MEMORY NOTE: ArgoCD's full install is heavy for the ~3.7 GB Docker VM this
# assessment was built on. Redis HA and the ApplicationSet controller are
# scaled to zero below; neither is needed for a single-application demo.
set -euo pipefail

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


REPO_URL="${1:-}"
ARGOCD_VERSION="${ARGOCD_VERSION:-v2.13.2}"
NS=argocd
APP_NS=payments

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }

[ -n "$REPO_URL" ] || die "usage: $0 <git-repo-url>
The Application needs a repository to sync FROM. GitOps has no meaning without
a source of truth, so this is required rather than defaulted."

kubectl get ns "$APP_NS" >/dev/null 2>&1 \
  || die "namespace '$APP_NS' not found, run task-1-workload-hardening/scripts/deploy.sh first"

log "Installing ArgoCD ${ARGOCD_VERSION}"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
# --server-side: the ArgoCD CRDs exceed the 262144-byte annotation limit that a
# client-side apply would try to write into last-applied-configuration.
kubectl apply -n "$NS" --server-side --force-conflicts \
  -f "https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/install.yaml"

log "Trimming components not needed for a single-app demo (memory)"
kubectl -n "$NS" scale deploy/argocd-applicationset-controller --replicas=0 2>/dev/null || true
kubectl -n "$NS" scale deploy/argocd-notifications-controller --replicas=0 2>/dev/null || true
kubectl -n "$NS" scale deploy/argocd-dex-server --replicas=0 2>/dev/null || true

log "Waiting for the core controllers"
kubectl -n "$NS" rollout status deploy/argocd-repo-server --timeout=420s
kubectl -n "$NS" rollout status deploy/argocd-server      --timeout=420s
kubectl -n "$NS" rollout status statefulset/argocd-application-controller --timeout=420s

log "Registering the ledger-api Application against ${REPO_URL}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
sed "s|https://github.com/REPLACE_ME/dodo-payments-devsecops-assessment.git|${REPO_URL}|" \
  "$HERE/argocd/application.yaml" > "$TMP/application.yaml"
grep -q REPLACE_ME "$TMP/application.yaml" && die "repoURL substitution failed"
kubectl apply -f "$TMP/application.yaml"

log "Admin password (change or delete this Secret in any real environment)"
kubectl -n "$NS" get secret argocd-initial-admin-secret \
  -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null || \
  warn "initial admin secret not present yet"
echo

cat <<EOF

Next steps
----------
Open the UI:
    kubectl port-forward -n ${NS} svc/argocd-server 8081:443
    # then https://localhost:8081  (user: admin)

Watch the Application reconcile:
    kubectl get application ledger-api -n ${NS} -w

Demonstrate drift detection and self-heal:
    ./task-2-cicd-supply-chain/scripts/demo-drift.sh

NOTE: the manifests in gitops/ reference ghcr.io/REPLACE_ME/ledger-api. Until
the CI pipeline has pushed a real image, either
  - run demo-drift.sh, which patches the image to the locally-built one, or
  - push to GitHub so the pipeline publishes and pins a signed digest.
EOF
