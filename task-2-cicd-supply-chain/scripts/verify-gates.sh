#!/usr/bin/env bash
#
# Task 2, prove the security gates actually gate.
#
# Runs each scanner locally in the same container image CI uses, and runs
# NEGATIVE tests: plant a known-bad input and assert the gate goes red.
#
# Why the negative tests matter more than the positive ones:
# a scanner that reports nothing looks exactly the same whether it is working
# perfectly or silently misconfigured. This file exists because an earlier
# revision of .gitleaks.toml re-declared a built-in rule with no regex, which
# would have disabled it while still reporting a reassuring green.
#
#   ./task-2-cicd-supply-chain/scripts/verify-gates.sh
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


HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_WIN="$(cd "$HERE" && pwd -W 2>/dev/null || echo "$HERE")"
export MSYS_NO_PATHCONV=1

SCRATCH="${TMPDIR:-/tmp}/task2-gates.$$"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"; rm -f "$HERE/task-2-cicd-supply-chain/gate-probe"*.yaml' EXIT

pass=0; fail=0
ok() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; pass=$((pass+1)); }
no() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=$((fail+1)); }
sec() { printf '\n\033[1;34m--- %s ---\033[0m\n' "$*"; }

command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }

GITLEAKS_IMG=zricethezav/gitleaks:latest
TRIVY_IMG=aquasec/trivy:latest

gitleaks_scan() {
  docker run --rm -v "${REPO_WIN}:/repo" "$GITLEAKS_IMG" \
    detect --source=/repo --config=/repo/.gitleaks.toml \
    --no-banner --redact --no-git 2>&1
}

sec "GATE 1: secrets scan (gitleaks)"

# Parse the config before doing anything else. A malformed .gitleaks.toml makes
# gitleaks exit 1 with "unable to load gitleaks config", which looks identical
# to a failing gate in CI logs but means the scan never ran at all.
#
# This is not hypothetical: a bulk punctuation edit once turned two array
# separators in that file from "," into ".", and the breakage only surfaced on
# a GitHub runner.
if python -c "import tomllib,sys;tomllib.load(open('$HERE/.gitleaks.toml','rb'))" 2>/dev/null; then
  ok ".gitleaks.toml is valid TOML"
else
  no ".gitleaks.toml does not parse; gitleaks will refuse to run"
  python -c "import tomllib;tomllib.load(open('$HERE/.gitleaks.toml','rb'))" 2>&1 | tail -2
fi

out="$(gitleaks_scan)"
if echo "$out" | grep -q "no leaks found"; then
  ok "clean tree scans clean"
else
  no "unexpected finding in a clean tree:"; echo "$out" | grep -E "File:|RuleID:" | head -4
fi

# NEGATIVE 1, a real-shaped token in an ordinary file must be caught.
#
# Two subtleties, both found the hard way:
#
#   a) The probe uses a GitHub PAT shape. An earlier version used `sk_live_...`
#      and the AWS `...EXAMPLEKEY` string; gitleaks ignores well-known
#      documentation values by design, so the test passed vacuously and made a
#      working scanner look broken.
#
#   b) The probe file must NOT be dot-prefixed. gitleaks skips hidden files.
#      so a probe named `.gate-probe.yaml` is never scanned and the negative
#      test passes vacuously, reporting a healthy gate while proving nothing.
#
#   c) The token is ASSEMBLED AT RUNTIME, never written as a literal. A literal
#      would make this script a permanent gitleaks finding, the test fixture
#      would fail the very gate it exists to validate. That is not theoretical:
#      the first version of this file was flagged twice by our own scan.
PROBE_PREFIX='ghp'
PROBE_TOKEN="${PROBE_PREFIX}_16C7e42F292c6912E7710c838347Ae178B4a"
printf 'token = "%s"\n' "$PROBE_TOKEN" \
  > "$HERE/task-2-cicd-supply-chain/gate-probe.yaml"
# Capture to a variable BEFORE grepping. `gitleaks_scan | grep -q ...` looks
# equivalent but is not: gitleaks exits 1 when it finds leaks, and with
# `set -o pipefail` the pipeline adopts that 1 rather than grep's 0, so a
# successfully-detected leak reads as a failed test. Command substitution in an
# assignment does not propagate the exit status, so this form is safe.
probe_out="$(gitleaks_scan)"
if echo "$probe_out" | grep -qE "leaks found: [1-9]"; then
  ok "NEGATIVE: planted token in an ordinary file is caught"
else
  no "NEGATIVE: planted token was NOT caught, the gate is not gating"
fi
rm -f "$HERE/task-2-cicd-supply-chain/gate-probe.yaml"

# NEGATIVE 2, the SealedSecret allowlist must not be bypassable by filename
# alone from an arbitrary directory.
printf 'token = "%s"\n' "$PROBE_TOKEN" \
  > "$HERE/task-2-cicd-supply-chain/gate-probe-sealedsecret.yaml"
probe_out="$(gitleaks_scan)"
if echo "$probe_out" | grep -qE "leaks found: [1-9]"; then
  ok "NEGATIVE: 'sealedsecret' filename outside manifests/secrets/ is still scanned"
else
  no "NEGATIVE: allowlist is bypassable by filename alone, tighten the path regex"
fi
rm -f "$HERE/task-2-cicd-supply-chain/gate-probe-sealedsecret.yaml"

sec "SealedSecret schema check (backs the allowlist)"
# The gitleaks allowlist trusts files under manifests/secrets/ named
# *sealedsecret*. Assert they really are ciphertext-only, so that trust holds.
shopt -s nullglob
for f in "$HERE"/task-*/manifests/secrets/*sealed*secret*.y*ml "$HERE"/task-*/gitops/*sealed*secret*.y*ml; do
  base="${f#$HERE/}"
  if ! grep -q 'kind: SealedSecret' "$f"; then
    no "$base is allowlisted but is not kind: SealedSecret"
  elif ! grep -q 'encryptedData' "$f"; then
    no "$base has no encryptedData block"
  elif grep -qE '^\s*(stringData|data):' "$f"; then
    no "$base contains a plaintext data/stringData key"
  else
    ok "$base is ciphertext-only (kind: SealedSecret + encryptedData, no plaintext)"
  fi
done
shopt -u nullglob

sec "GATE 3/4: CVE scan (Trivy), fail-policy arithmetic"
# The policy blocks on FIXABLE critical/high and warns on unfixed. Verify the
# two counts differ, i.e. that --ignore-unfixed is doing real work rather than
# being a no-op that quietly blocks everything anyway.
IMG_TAR="$SCRATCH/img.tar"
if docker image inspect ledger-api:0.1.0 >/dev/null 2>&1; then
  docker save ledger-api:0.1.0 -o "$IMG_TAR" 2>/dev/null
  TAR_WIN="$(cd "$SCRATCH" && pwd -W 2>/dev/null || echo "$SCRATCH")"

  # ONE scan, both numbers. A vulnerability is "fixable" exactly when Trivy
  # reports a FixedVersion, so --ignore-unfixed is just a filter over the same
  # data, running the scan twice would double the work for no extra
  # information. That matters here: two concurrent Trivy runs starved the k3d
  # cluster's API server on this 3.7 GB Docker VM and made it unreachable.
  docker run --rm -v "${TAR_WIN}:/scan" "$TRIVY_IMG" image \
    --scanners vuln --severity CRITICAL,HIGH --quiet --timeout 15m \
    --format json --output /scan/scan.json --input /scan/img.tar 2>/dev/null

  # Hand python the WINDOWS path. MSYS_NO_PATHCONV=1 is set above so Git Bash
  # leaves container paths alone, but that also means a Unix-style
  # "/tmp/task2-gates.NNN/scan.json" reaches Windows python verbatim, and it
  # cannot resolve it. TAR_WIN is the same directory in a form python accepts.
  COUNTS="$(python - "$TAR_WIN/scan.json" <<'PY' 2>/dev/null
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
v=[x for r in d.get("Results",[]) for x in (r.get("Vulnerabilities") or [])]
print(len(v), sum(1 for x in v if x.get("FixedVersion")))
PY
)"
  ALL="$(echo "$COUNTS" | awk '{print $1}')"
  FIXABLE="$(echo "$COUNTS" | awk '{print $2}')"

  if [ -n "${ALL:-}" ] && [ -n "${FIXABLE:-}" ]; then
    UNFIXED=$((ALL - FIXABLE))
    printf '  total CRITICAL+HIGH : %s\n' "$ALL"
    printf '  fixable (BLOCKS)    : %s\n' "$FIXABLE"
    printf '  unfixed (WARNS)     : %s\n' "$UNFIXED"
    [ "$UNFIXED" -gt 0 ] \
      && ok "unfixed findings exist, so --ignore-unfixed is materially different from blocking on everything" \
      || no "no unfixed findings, cannot demonstrate the unfixed-CVE policy on this image"
    [ "$FIXABLE" -gt 0 ] \
      && ok "fixable findings exist, so the blocking gate would correctly go red on this image" \
      || ok "no fixable findings, gate would pass"
  else
    no "Trivy scan produced no parseable output"
  fi
else
  printf '  \033[1;33mSKIP\033[0m  ledger-api:0.1.0 not present locally (run Task 1 deploy.sh first)\n'
fi

printf '\n\033[1m=== %d passed, %d failed ===\033[0m\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
