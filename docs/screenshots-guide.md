# Screenshots Guide

What to capture as evidence, and the exact command for each shot.

The assessment says *"Show it working, screenshots, terminal recordings, or
pipeline run links are how we verify."* Reviewers skim. Each screenshot should
prove **one** claim, with the command visible in the same frame as its output.

## Rules of thumb

- **Command + output in one frame.** A wall of output with no command proves nothing.
- **Keep the prompt visible** so the namespace/context is obvious.
- **Do not crop out failures.** A rejection message *is* the evidence for a guardrail.
- **Widen the terminal** to ~120 columns so lines do not wrap.
- Save as `taskN-NN-short-name.png` in `task-N-.../screenshots/`.
- Terminal recordings (asciinema / Windows Terminal capture) beat stills where
  something takes time to happen, a rollout, a policy rejection, a pipeline run.

---

## Task 1: Deploy & Harden the Workload

Nine shots. Run each command, screenshot the result.

> Prereq: cluster running (`./scripts/deploy.sh`), context `k3d-ledger`.

### 1-01  Cluster and workload running
Proves: the hardened workload actually deploys.
```bash
kubectl get nodes && kubectl get pods,svc,ingress -n payments
```

### 1-02  THE MONEY SHOT: original insecure Deployment rejected
Proves: the admission guardrail blocks the starter manifest. Capture the
`Warning:` line **and** the `0/3`, that pairing is the whole story.
```bash
kubectl apply -f app-source/deploy/deployment.yaml
kubectl get deploy ledger-api -n payments
kubectl get pods -n payments
kubectl delete -f app-source/deploy/deployment.yaml
```

### 1-03  Runtime hardening: non-root, read-only rootfs, no token
Proves: controls are enforced at runtime, not merely written in YAML.
```bash
POD=$(kubectl get pod -n payments -l app.kubernetes.io/name=ledger-api -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n payments $POD -- id
kubectl exec -n payments $POD -- sh -c 'echo pwned > /malware.sh'
kubectl exec -n payments $POD -- ls /var/run/secrets/kubernetes.io/serviceaccount/
```
Expect: `uid=10001`, `Read-only file system`, `No such file or directory`.
The two errors are the evidence, keep them in shot.

### 1-04  securityContext as applied
Proves: caps dropped, seccomp on, no privilege escalation.
```bash
kubectl get pod -n payments $POD -o jsonpath='{range .spec.containers[*]}caps={.securityContext.capabilities.drop}{"\n"}ro_rootfs={.securityContext.readOnlyRootFilesystem}{"\n"}privesc={.securityContext.allowPrivilegeEscalation}{"\n"}seccomp={.securityContext.seccompProfile.type}{"\n"}{end}'
```

### 1-05  Kyverno policies rejecting violations
Proves: guardrails catch root, `:latest`, missing limits, writable rootfs.
Easiest capture, the verify script's section 8:
```bash
bash scripts/verify.sh 2>&1 | sed -n '/8\. Admission/,/9\. RBAC/p'
```

### 1-06  Policies active
Proves: four policies loaded, and *why* one is Audit.
```bash
kubectl get clusterpolicy
kubectl get ns payments --show-labels
```
The namespace labels show PSS `restricted` enforced. Mention in your write-up
that `verify-image-signature` is intentionally `Audit` until Task 2 signs images.

### 1-07  Secrets: ciphertext only, no plaintext
Proves: the plaintext key is gone from git.
```bash
head -12 manifests/secrets/ledger-api-sealedsecret.yaml
grep -rc "sk_live" manifests/ || echo "no plaintext key anywhere in manifests/"
kubectl get sealedsecret,secret ledger-api-secrets -n payments
```

### 1-08  RBAC least privilege
Proves: no persona can read Secrets or exec.
```bash
for g in developers operators admins; do
  printf '%-32s secrets=%s exec=%s\n' "dodo:payments-$g" \
    "$(kubectl auth can-i get secrets -n payments --as=probe --as-group=dodo:payments-$g)" \
    "$(kubectl auth can-i create pods --subresource=exec -n payments --as=probe --as-group=dodo:payments-$g)"
done
```
Use `--subresource=exec`, **not** `pods/exec`, the slash form reports a false `yes`.

### 1-09  Ingress: TLS + security headers
Proves: the Ingress requirement works end to end.
```bash
kubectl port-forward -n ingress-nginx svc/ingress-nginx-controller 8443:443 &
curl -skI --resolve ledger.local:8443:127.0.0.1 https://ledger.local:8443/health
curl -sk  --resolve ledger.local:8443:127.0.0.1 https://ledger.local:8443/health
```

### 1-10  Full verification suite (the summary shot)
Proves everything at once. If you only submit one screenshot, make it this.
```bash
bash scripts/verify.sh
```
Capture the final `=== 17 passed, 0 failed ===`.

---

## Task 2: Secure CI/CD & Supply Chain

Local shots can be taken now; the GitHub ones need the repo pushed.

### Local (available immediately)

**2-01  Security gates verified, including negative tests**
The headline local shot. Capture the `passed, 0 failed` line.
```bash
bash task-2-cicd-supply-chain/scripts/verify-gates.sh
```

**2-02  The fail-policy data**
Shows *why* the policy is "block fixable, warn unfixed" with real numbers.
```bash
sed -n '1,30p' task-2-cicd-supply-chain/evidence/01-trivy-image-scan.txt
```

**2-03  Secrets gate proven to go red**
The negative tests are the evidence. A green secrets gate proves nothing on its own.
```bash
cat task-2-cicd-supply-chain/evidence/02-gitleaks-gates.txt
```

**2-04  ArgoCD drift detection + self-heal**
Requires `bootstrap-argocd.sh` to have run. A terminal recording beats a still
here, since the revert happens over ~20s.
```bash
bash task-2-cicd-supply-chain/scripts/demo-drift.sh
```

**2-05  ArgoCD UI: Synced/Healthy**
```bash
kubectl port-forward -n argocd svc/argocd-server 8081:443
# https://localhost:8081, screenshot the app tile and the resource tree
```

### After pushing to GitHub

**2-06  Actions run: all gates green**
The run summary page showing the job graph (3 parallel gates → build → scan →
sign → gitops). Capture the whole graph, not one job.

**2-07  A gate BLOCKING (most valuable shot in Task 2)**
Anyone can screenshot a green pipeline. Show it *failing correctly*: open a PR
that adds a real-shaped token, and capture the red `secrets-scan` job with the
gitleaks finding. Delete the branch afterwards.

**2-08  `cosign verify` output**
From the `sign-and-attest` job log, or the `supply-chain-evidence` artifact.
Must show the certificate identity and OIDC issuer, that's what proves *which
workflow* signed it, not merely that something signed it.

**2-09  GitHub Security tab (SARIF)**
Code scanning alerts from all three categories: `semgrep`, `trivy-fs`,
`trivy-image`.

**2-10  GHCR package with signature**
The package page showing the image plus its `.sig` and `.att` artifacts.

## Task 3: Service Mesh & Zero-Trust *(pending)*

- `istioctl proxy-status` / sidecars injected
- Plaintext request **refused** under mTLS STRICT
- Authorised caller allowed vs unauthorised caller denied (RBAC deny in logs)
- NetworkPolicy blocking traffic the mesh policy allows, and vice versa

## Task 4: Recon & Pen Test *(pending)*

- crt.sh / subfinder subdomain output
- httpx fingerprint table
- Per finding: the request/response pair proving it (Burp or curl)
- Retest showing the finding closed
