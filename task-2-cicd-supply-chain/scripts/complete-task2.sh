#!/usr/bin/env bash
#
# Finish Task 2 end to end once the two manual prerequisites are done:
#
#   1. gh auth login          (only you can do this, it needs your credentials)
#   2. enough free RAM for Docker to start (~2.5 GB)
#
# Everything after that is automated here: create the repo, push, watch the
# pipeline, pull down the cosign proof, bootstrap ArgoCD against the new remote,
# run the drift demo, and write the evidence files.
#
#   ./task-2-cicd-supply-chain/scripts/complete-task2.sh [repo-name]
#
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


REPO_NAME="${1:-dodo-payments-devsecops-assessment}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE="$HERE/task-2-cicd-supply-chain/evidence"
mkdir -p "$EVIDENCE"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }

cd "$HERE"

# Preflight. Fail loudly and early rather than half-way through a push.
log "Preflight"

command -v gh >/dev/null || die "gh not found on PATH"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated. Run: gh auth login"
echo "  gh authenticated as: $(gh api user --jq .login 2>/dev/null)"

# Docker is NOT required for most of this script. The repo push, the pipeline,
# the image build, cosign signing and the SARIF upload all happen on GitHub's
# runners. Only the ArgoCD stage at the end needs a local cluster, so a missing
# Docker daemon degrades that one stage instead of blocking everything.
DOCKER_OK=0
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  DOCKER_OK=1
  echo "  docker up (ArgoCD stage will run)"
else
  warn "Docker is not running. Everything except the ArgoCD/GitOps stage will"
  warn "still run; that stage will be skipped and can be done later with:"
  warn "  ./task-2-cicd-supply-chain/scripts/bootstrap-argocd.sh <repo-url>"
  warn "  ./task-2-cicd-supply-chain/scripts/demo-drift.sh"
fi

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git repository"
if [ -n "$(git status --porcelain)" ]; then
  warn "working tree is dirty; committing before push"
  git add -A
  git commit -q -m "chore: pre-push snapshot" || true
fi

OWNER="$(gh api user --jq .login)"

# Create the repository and push.
log "Creating public repository ${OWNER}/${REPO_NAME}"

if gh repo view "${OWNER}/${REPO_NAME}" >/dev/null 2>&1; then
  echo "  repo already exists, reusing"
  git remote get-url origin >/dev/null 2>&1 \
    || git remote add origin "https://github.com/${OWNER}/${REPO_NAME}.git"
  git push -u origin HEAD:main
else
  # --public is required: the assessment asks for a public repository, and
  # cosign keyless verification against a private GHCR package is a lot more
  # awkward for a reviewer to check.
  gh repo create "${REPO_NAME}" --public --source=. --remote=origin --push
fi

REPO_URL="https://github.com/${OWNER}/${REPO_NAME}.git"
echo "  pushed to ${REPO_URL}"

# Watch the pipeline.
log "Waiting for the ci-cd workflow"

sleep 10
RUN_ID="$(gh run list --workflow=ci-cd --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null)"
if [ -z "${RUN_ID:-}" ]; then
  warn "no workflow run found yet. Check: gh run list"
else
  echo "  run id: $RUN_ID"
  echo "  watching (this takes several minutes)..."
  gh run watch "$RUN_ID" --exit-status || warn "the run did not finish green, see below"
  echo
  gh run view "$RUN_ID" --json jobs \
    --jq '.jobs[] | "  \(.conclusion // .status)\t\(.name)"' 2>/dev/null
fi

# Collect the supply-chain proof.
log "Collecting cosign evidence"

{
  echo "======================================================================"
  echo " EVIDENCE: supply chain, signed image and attestation"
  echo " Repo   : ${OWNER}/${REPO_NAME}"
  echo " Run    : ${RUN_ID:-unknown}"
  echo "======================================================================"
  echo
  echo "Workflow jobs:"
  gh run view "${RUN_ID:-}" --json jobs \
    --jq '.jobs[] | "  \(.conclusion // .status)  \(.name)"' 2>/dev/null || echo "  (unavailable)"
  echo
  echo "--- cosign verify (from the sign-and-attest job) ---"
  rm -rf "$EVIDENCE/_artifact"
  if gh run download "${RUN_ID:-}" -n supply-chain-evidence -D "$EVIDENCE/_artifact" 2>/dev/null; then
    cat "$EVIDENCE/_artifact/cosign-verify.txt" 2>/dev/null || echo "  (no cosign-verify.txt in artifact)"
    if [ -f "$EVIDENCE/_artifact/sbom.spdx.json" ]; then
      echo
      echo "--- SBOM summary ---"
      python -c "
import json,sys
d=json.load(open(r'$EVIDENCE/_artifact/sbom.spdx.json',encoding='utf-8'))
pkgs=d.get('packages',[])
print(f'  SPDX document with {len(pkgs)} packages')
for p in pkgs[:15]:
    print('   ', p.get('name'), p.get('versionInfo',''))
" 2>/dev/null || echo "  (could not summarise)"
    fi
  else
    echo "  artifact not available (the signing job may not have run)"
  fi
  echo
  echo "--- verify locally against the published image ---"
  echo "cosign verify \\"
  echo "  --certificate-identity-regexp \"^https://github.com/${OWNER}/${REPO_NAME}/\\.github/workflows/.+@refs/heads/main\$\" \\"
  echo "  --certificate-oidc-issuer \"https://token.actions.githubusercontent.com\" \\"
  echo "  ghcr.io/${OWNER}/ledger-api:<tag>"
} > "$EVIDENCE/03-supply-chain-signing.txt" 2>&1
rm -rf "$EVIDENCE/_artifact"
echo "  wrote $EVIDENCE/03-supply-chain-signing.txt"

# SARIF landed in the Security tab.
log "Code scanning results"
{
  echo "======================================================================"
  echo " EVIDENCE: SARIF uploads in the Security tab"
  echo "======================================================================"
  echo
  gh api "repos/${OWNER}/${REPO_NAME}/code-scanning/alerts?per_page=100" \
    --jq 'group_by(.tool.name)[] | "\(.[0].tool.name): \(length) alerts"' 2>/dev/null \
    || echo "(code scanning not populated yet, or the runs are still in progress)"
  echo
  echo "Browse: https://github.com/${OWNER}/${REPO_NAME}/security/code-scanning"
} > "$EVIDENCE/04-sarif-security-tab.txt" 2>&1
cat "$EVIDENCE/04-sarif-security-tab.txt" | tail -5

# GitOps.
log "Bootstrapping ArgoCD against ${REPO_URL}"

if [ "$DOCKER_OK" -eq 0 ] || ! kubectl get nodes >/dev/null 2>&1; then
  warn "no reachable cluster; skipping ArgoCD. Once Docker is up, run:"
  warn "  ./task-1-workload-hardening/scripts/deploy.sh    # if the cluster is gone"
  warn "  ./task-2-cicd-supply-chain/scripts/bootstrap-argocd.sh ${REPO_URL}"
  warn "  ./task-2-cicd-supply-chain/scripts/demo-drift.sh"
else
  # ArgoCD is memory-hungry. On a ~3.7 GB Docker VM it competes with Kyverno
  # for the same headroom, and both being starved is worse than either being
  # scaled down. Kyverno's policies stay installed as CRDs; only the running
  # controllers pause, and they come back with the restore line printed below.
  if kubectl -n kyverno get deploy >/dev/null 2>&1; then
    warn "scaling Kyverno controllers to 0 to make room for ArgoCD"
    kubectl -n kyverno scale deploy --all --replicas=0 >/dev/null 2>&1
    echo "  restore later with: kubectl -n kyverno scale deploy --all --replicas=1"
  fi

  bash "$HERE/task-2-cicd-supply-chain/scripts/bootstrap-argocd.sh" "$REPO_URL" \
    && bash "$HERE/task-2-cicd-supply-chain/scripts/demo-drift.sh" \
    || warn "ArgoCD stage did not complete; see output above"
fi

log "Done"
cat <<EOF

Repository : https://github.com/${OWNER}/${REPO_NAME}
Actions    : https://github.com/${OWNER}/${REPO_NAME}/actions
Security   : https://github.com/${OWNER}/${REPO_NAME}/security/code-scanning
Package    : https://github.com/${OWNER}?tab=packages

Evidence written to task-2-cicd-supply-chain/evidence/.

Remaining manual step: flip Task 1's Kyverno signature policy from Audit to
Enforce now that GHCR holds signed images. Edit
task-1-workload-hardening/manifests/policy/04-verify-image-signature.yaml:
  validationFailureAction: Enforce
  mutateDigest: true
then re-apply it.
EOF
