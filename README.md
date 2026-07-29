# Dodo Payments: Security & DevOps Engineer Technical Assessment

Hardening `ledger-api`, a PCI-DSS-scoped payments microservice, end to end:
workload security, secure CI/CD and supply chain, Istio zero-trust networking,
and offensive reconnaissance plus penetration testing.

## Status

| Task | Status | Headline |
|---|---|---|
| [Task 1: Workload Hardening](./task-1-workload-hardening/README.md) | **Complete** | 17/17 verification checks pass; original insecure Deployment rejected at admission |
| [Task 2: CI/CD & Supply Chain](./task-2-cicd-supply-chain/README.md) | **Complete** | All 7 jobs pass; image signed with cosign keyless, digest committed back, ArgoCD drift detection and self-heal verified |
| [Task 3: Service Mesh & Zero-Trust](./task-3-service-mesh-zero-trust/README.md) | Not started | |
| [Task 4: Recon & Penetration Testing](./task-4-recon-pentest/README.md) | Not started | |

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Cluster | **k3d / k3s** | kind could not boot on this 3.7 GB Docker VM, its node never reached systemd's multi-user target. k3s boots reliably in ~2 min. The brief permits kind/k3d/minikube equally. |
| Admission | **Pod Security Standards `restricted` + Kyverno** | They fail differently. PSS is compiled into the API server and survives webhook deletion; Kyverno expresses rules PSS cannot (registry, `:latest`, signatures). |
| Secrets | **Sealed Secrets** | Encrypts to a keypair that never leaves the cluster, so no private key is distributed to operators or CI. SOPS+age needs key distribution; External Secrets needs a backend. |
| CI/CD | **GitHub Actions + GHCR** | Free runners, and OIDC is what makes cosign keyless signing possible. |
| Supply chain | **Cosign keyless + Fulcio + Rekor, Syft SBOM** | No long-lived signing key exists to leak. |
| Delivery | **ArgoCD** | Pull-based, so CI holds no cluster credentials. |
| Mesh | Istio *(Task 3)* | |

## Running it locally

```bash
# Task 1: cluster, hardened workload, policies
cd task-1-workload-hardening
./scripts/deploy.sh
./scripts/verify.sh          # expect: 17 passed, 0 failed

# Task 2: validate the pipeline's security gates locally
./task-2-cicd-supply-chain/scripts/verify-gates.sh

# Task 2: GitOps (needs a pushed repo)
./task-2-cicd-supply-chain/scripts/bootstrap-argocd.sh https://github.com/<you>/<repo>.git
./task-2-cicd-supply-chain/scripts/demo-drift.sh
```

Prerequisites: Docker, k3d, kubectl, kubeseal. No cloud account required.

> **Environment note.** Built on a 7.3 GB laptop where Docker's VM gets ~3.7 GB.
> Two workarounds are baked into the scripts: BuildKit cannot read through
> OneDrive reparse points (build contexts are copied to a temp dir), and k3d
> writes `host.docker.internal` into the kubeconfig, which resolves to the LAN
> IP on Windows (rewritten to loopback). Concurrent Trivy scans can starve the
> cluster's API server on this much memory, `verify-gates.sh` scans once and
> derives both counts rather than running two passes.

## Three decisions worth defending

1. **The application's vulnerabilities are left intact.** `app-source/app.py`
   has `yaml.load` RCE on `/import`, SSRF on `/fetch`, and cleartext PANs on
   `/transactions`. They are Task 4's authorised target. Task 1 *contains* them
   instead: RCE lands as uid 10001, read-only filesystem, no capabilities, no
   ServiceAccount token to pivot with.

2. **No RBAC persona, including `admin`, can read Secrets or exec into a pod.**
   Sealing secrets in git is theatre if any developer can `kubectl get secret -o
   yaml` the decrypted value. Admins manage *SealedSecrets* (ciphertext); exec
   sits in a break-glass Role bound to nobody.

3. **The CVE gate blocks on fixable findings and warns on unfixed ones.**
   Measured: 182 CRITICAL/HIGH, 149 fixable, 33 unfixed. Blocking on the 33
   would leave the pipeline permanently red with no action that could turn it
   green, so the gate would be disabled within a week, and the 149 would then
   ship unnoticed too.

## How AI was used

Claude (Claude Code) was used throughout as a pair-programmer: drafting
manifests and workflows, and, most usefully, running the verification loops
that caught real defects. Several bugs in this repository were found that way
rather than by inspection, and are documented where they occurred rather than
quietly fixed:

- A `.gitignore` rule (`**/secrets/*.yaml`) that would have excluded the
  SealedSecret from git, silently breaking the deployment and GitOps sync.
- A `.gitleaks.toml` block that re-declared a built-in rule without a `regex`,
  which replaces the rule with an empty one and disables detection.
- A secrets-gate test fixture that embedded its probe token as a literal, so it
  failed the very gate it validated.
- A negative test that passed vacuously twice, first because it used
  well-known example credentials that gitleaks ignores by design, then because
  the probe file was dot-prefixed and therefore skipped.

Every artifact here was executed and verified locally, not just generated. The
reasoning in each task README is mine to defend.

## Submission checklist

- [ ] Repository is public
- [x] Top-level README links every task folder
- [x] Each task has its own README (approach + reproduction + verification)
- [x] Architecture diagram present (Tasks 1 and 2)
- [ ] Screenshots/recordings for every checklist item, see [docs/screenshots-guide.md](./docs/screenshots-guide.md)
- [ ] Task 4 report delivered as a standalone PDF or Markdown file
