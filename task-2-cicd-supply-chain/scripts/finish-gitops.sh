#!/usr/bin/env bash
#
# Finish the one outstanding piece of Task 2: the ArgoCD drift/self-heal demo.
#
#   bash task-2-cicd-supply-chain/scripts/finish-gitops.sh
#
# Prerequisite: Docker Desktop running with roughly 2.5 GB free. Everything
# else, restarting or rebuilding the cluster, freeing memory for ArgoCD,
# passing the repo URL, is handled here.
#
# Written because the sequence has three easy-to-miss steps: the k3d cluster
# stops with Docker and has to be restarted, ArgoCD does not fit alongside
# Kyverno on a ~3.7 GB VM, and bootstrap-argocd.sh requires the repository URL
# as an argument.
set -uo pipefail

REPO_URL="${1:-https://github.com/JubethSB/dodo-payments-devsecops-assessment.git}"
CLUSTER=ledger
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }

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

missing=""
for t in docker k3d kubectl; do
  command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
[ -z "$missing" ] || die "could not find:$missing

Looked on PATH, in Docker Desktop's resources/bin, and under winget's
Links and Packages directories. If they are installed somewhere else, add
that directory to PATH and run this again."

log "Checking Docker"
if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running.

Start Docker Desktop and wait 4-5 minutes for it to finish booting, then run
this again. It needs roughly 2.5 GB free; close browser windows and spare
editors first if it refuses to start."
fi
echo "  docker up"

log "Making sure the cluster is running"
if k3d cluster list 2>/dev/null | grep -q "^${CLUSTER} "; then
  # k3d nodes are containers; they stop when Docker stops and need starting
  # again, which is quick. Recreating from scratch would be several minutes.
  k3d cluster start "$CLUSTER" 2>&1 | tail -2 || true
else
  warn "cluster '$CLUSTER' does not exist; rebuilding it from Task 1"
  bash "$HERE/task-1-workload-hardening/scripts/deploy.sh" || die "deploy.sh failed"
fi

# k3d writes host.docker.internal into the kubeconfig, which resolves to the
# LAN IP on Windows and times out. The port also changes when the cluster
# restarts, so this has to be redone every time rather than once at creation.
API_PORT="$(docker port "k3d-${CLUSTER}-serverlb" 6443/tcp 2>/dev/null | head -1 | sed 's/.*://')"
if [ -n "${API_PORT:-}" ]; then
  kubectl config set-cluster "k3d-${CLUSTER}" --server="https://127.0.0.1:${API_PORT}" >/dev/null
  kubectl config use-context "k3d-${CLUSTER}" >/dev/null
fi

kubectl wait --for=condition=Ready node --all --timeout=300s >/dev/null 2>&1 \
  || die "cluster did not become ready"
echo "  cluster ready"

log "Freeing memory for ArgoCD"
# ArgoCD and Kyverno both want more than this VM has. Kyverno's CRDs and
# policies stay installed, only the running controllers pause, so nothing is
# lost; admission enforcement resumes when they scale back up.
if kubectl get ns kyverno >/dev/null 2>&1; then
  kubectl -n kyverno scale deploy --all --replicas=0 >/dev/null 2>&1
  echo "  Kyverno controllers scaled to 0"
  echo "  restore later: kubectl -n kyverno scale deploy --all --replicas=1"
fi

log "Bootstrapping ArgoCD against ${REPO_URL}"
bash "$HERE/task-2-cicd-supply-chain/scripts/bootstrap-argocd.sh" "$REPO_URL" \
  || die "ArgoCD bootstrap failed"

log "Running the drift and self-heal demo"
bash "$HERE/task-2-cicd-supply-chain/scripts/demo-drift.sh" \
  || warn "drift demo did not complete cleanly; see output above"

log "Done"
cat <<EOF

Evidence written to task-2-cicd-supply-chain/evidence/05-argocd-drift-selfheal.txt

ArgoCD UI:
    kubectl port-forward -n argocd svc/argocd-server 8081:443
    # https://localhost:8081, user admin

Restore Kyverno enforcement when finished:
    kubectl -n kyverno scale deploy --all --replicas=1
EOF
