#!/usr/bin/env bash
#
# Screenshot helper for Task 1.
#
# Runs each evidence command behind a clear banner and pauses so you can
# capture the frame. The command is echoed above its own output, which is what
# makes a screenshot self-explanatory to a reviewer.
#
#   ./scripts/screenshots.sh          # all shots, pausing between each
#   ./scripts/screenshots.sh 2        # just shot 2
#   ./scripts/screenshots.sh --no-pause
#
set -uo pipefail

NS=payments
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

PAUSE=1
WANT=""
for a in "$@"; do
  case "$a" in
    --no-pause) PAUSE=0 ;;
    [0-9]*)     WANT="$a" ;;
  esac
done

banner() {
  printf '\n\033[1;44m                                                                      \033[0m\n'
  printf '\033[1;44m  SHOT %-63s\033[0m\n' "$1"
  printf '\033[1;44m                                                                      \033[0m\n'
  printf '\033[0;36m%s\033[0m\n\n' "$2"
}
run() { printf '\033[1;32m$\033[0m %s\n' "$1"; eval "$1" 2>&1; echo; }
hold() {
  [ "$PAUSE" -eq 1 ] || return 0
  printf '\033[1;33m--- screenshot now, then press Enter ---\033[0m'
  read -r _ </dev/tty || true
  clear
}
want() { [ -z "$WANT" ] || [ "$WANT" = "$1" ]; }

POD="$(kubectl get pod -n $NS -l app.kubernetes.io/name=ledger-api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"

if want 1; then
banner "1-01  Cluster and workload running" "Proves: the hardened workload deploys and is Ready."
run "kubectl get nodes"
run "kubectl get pods,svc,ingress -n $NS"
hold
fi

if want 2; then
banner "1-02  Original INSECURE Deployment is REJECTED" "The money shot. Capture the Warning AND the 0/3."
run "kubectl apply -f app-source/deploy/deployment.yaml"
sleep 6
run "kubectl get deploy ledger-api -n $NS"
run "kubectl get pods -n $NS"
printf '\033[1;31m^^ zero pods admitted: every replica was refused at admission\033[0m\n\n'
kubectl delete -f app-source/deploy/deployment.yaml >/dev/null 2>&1
hold
fi

if want 3; then
banner "1-03  Runtime hardening" "Proves the controls are enforced at runtime, not just declared."
run "kubectl exec -n $NS $POD -- id"
printf '\033[1;32m$\033[0m kubectl exec -n %s %s -- sh -c '"'"'echo pwned > /malware.sh'"'"'\n' "$NS" "$POD"
kubectl exec -n $NS "$POD" -- sh -c 'echo pwned > /malware.sh' 2>&1; echo
printf '\033[1;32m$\033[0m kubectl exec -n %s %s -- ls /var/run/secrets/kubernetes.io/serviceaccount/\n' "$NS" "$POD"
MSYS_NO_PATHCONV=1 kubectl exec -n $NS "$POD" -- ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1; echo
printf '\033[1;31mBoth errors above are the evidence: read-only rootfs, no API token.\033[0m\n\n'
hold
fi

if want 4; then
banner "1-04  securityContext as applied" "Proves caps dropped, seccomp on, no privilege escalation."
run "kubectl get pod -n $NS $POD -o jsonpath='{range .spec.containers[*]}caps={.securityContext.capabilities.drop}{\"\\n\"}ro_rootfs={.securityContext.readOnlyRootFilesystem}{\"\\n\"}privesc={.securityContext.allowPrivilegeEscalation}{\"\\n\"}seccomp={.securityContext.seccompProfile.type}{\"\\n\"}{end}'"
hold
fi

if want 5; then
banner "1-05  Admission policies rejecting violations" "root / :latest / no-limits / writable-rootfs all refused."
bash scripts/verify.sh 2>&1 | sed -n '/8\. Admission/,/9\. RBAC/p' | head -12
echo
hold
fi

if want 6; then
banner "1-06  Policies active + PSS on the namespace" "Two enforcement layers, both live."
run "kubectl get clusterpolicy"
run "kubectl get ns $NS --show-labels"
printf '\033[0;36mNote: verify-image-signature is intentionally Audit until Task 2 signs images.\033[0m\n\n'
hold
fi

if want 7; then
banner "1-07  Secrets: ciphertext only" "Proves the plaintext key is gone from git."
run "head -12 manifests/secrets/ledger-api-sealedsecret.yaml"
NEEDLE='sk_live_''9f3a2b7c1e4d8'
if grep -rqF "$NEEDLE" manifests/ 2>/dev/null; then
  printf '\033[1;31mLEAKED KEY FOUND\033[0m\n'
else
  printf '\033[1;32mNo plaintext Stripe key anywhere under manifests/\033[0m\n'
fi
echo
run "kubectl get sealedsecret,secret ledger-api-secrets -n $NS"
hold
fi

if want 8; then
banner "1-08  RBAC least privilege" "No persona can read Secrets or exec into a pod."
printf '\033[1;32m$\033[0m for g in developers operators admins; do kubectl auth can-i ... ; done\n\n'
printf '  %-32s %-12s %s\n' PERSONA SECRETS EXEC
for g in developers operators admins; do
  printf '  %-32s %-12s %s\n' "dodo:payments-$g" \
    "$(kubectl auth can-i get secrets -n $NS --as=probe --as-group=dodo:payments-$g 2>&1)" \
    "$(kubectl auth can-i create pods --subresource=exec -n $NS --as=probe --as-group=dodo:payments-$g 2>&1)"
done
printf '\n\033[0;36mUse --subresource=exec, not pods/exec (the slash form reports a false yes).\033[0m\n\n'
hold
fi

if want 9; then
banner "1-09  Ingress: TLS + security headers" "Proves the Ingress requirement works end to end."
kubectl port-forward -n ingress-nginx svc/ingress-nginx-controller 8443:443 >/dev/null 2>&1 &
PF=$!; sleep 7
run "curl -skI --resolve ledger.local:8443:127.0.0.1 https://ledger.local:8443/health"
run "curl -sk --resolve ledger.local:8443:127.0.0.1 https://ledger.local:8443/health"
kill $PF 2>/dev/null
hold
fi

if want 10; then
banner "1-10  Full verification suite" "If you submit only one screenshot, make it this one."
bash scripts/verify.sh 2>&1 | grep -E 'PASS|FAIL|==='
echo
fi

printf '\n\033[1;32mDone. Save shots to task-1-workload-hardening/screenshots/ as task1-NN-name.png\033[0m\n'
