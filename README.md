# Dodo Payments: Security & DevOps Engineer Technical Assessment

[![CI](https://github.com/JubethSB/dodo-payments-devsecops-assessment/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/JubethSB/dodo-payments-devsecops-assessment/actions/workflows/ci-cd.yml)
![Kubernetes](https://img.shields.io/badge/Kubernetes-k3d-326CE5?logo=kubernetes&logoColor=white)
![Istio](https://img.shields.io/badge/Istio-mTLS%20STRICT-466BB0?logo=istio&logoColor=white)
![Supply chain](https://img.shields.io/badge/Supply%20chain-cosign%20keyless%20%2B%20SBOM-F97316?logo=sigstore&logoColor=white)
![Policy](https://img.shields.io/badge/Admission-PSS%20restricted%20%2B%20Kyverno-6E56CF)
![Scope](https://img.shields.io/badge/Scope-PCI%20DSS%20CDE-2EA043)

`ledger-api` from the starter repo, taken from the state it shipped in to
something that would survive a PCI audit. Workload hardening, a delivery
pipeline that actually gates, then zero-trust networking and offensive testing.

Runs locally on k3d. No cloud account.

| Task | State | |
|---|---|---|
| [1: Workload Hardening](./task-1-workload-hardening/README.md) | Done | 17/17 checks; starter Deployment rejected at admission |
| [2: CI/CD & Supply Chain](./task-2-cicd-supply-chain/README.md) | Done | 7/7 jobs; image signed keyless, drift self-heal verified |
| [3: Service Mesh & Zero-Trust](./task-3-service-mesh-zero-trust/README.md) | Done | Istio mTLS STRICT; SPIFFE authz (200 vs 403); NetworkPolicy; gateway + canary |
| [4: Recon & Pen Test](./task-4-recon-pentest/README.md) | Done | Passive OSINT of dodopayments.tech; 4 exploited findings on the local target, CVSS-scored |

## Engineering handover & design rationale

The [`docs/handover/`](./docs/handover/) directory is the full write-up behind the
decisions: per-task deep dives (threat model, why each tool over its
alternatives, the concepts in plain language, verification, and the problems
actually hit and root-caused), a [repository review & submission audit](./docs/handover/repository-review.md),
an [interview cheat sheet](./docs/handover/interview-cheat-sheet.md), and an
[executive summary](./docs/handover/executive-summary.md). Start there if you want
the *why*, not just the *what*.

## Stack, and why

**k3d/k3s** rather than kind. kind couldn't create a cluster on this machine's
3.7 GB Docker VM; the node never reached systemd's multi-user target, even
single-node. k3s boots in about two minutes. The brief allows either.

**PSS `restricted` + Kyverno**, both. They fail differently: PSS is in the API
server and survives someone deleting the webhook, Kyverno expresses rules PSS
can't (registry, `:latest`, signatures).

**Sealed Secrets** over SOPS+age or External Secrets. SOPS needs a private key
distributed to operators and CI; Sealed Secrets encrypts to a keypair that never
leaves the cluster. External Secrets is better at scale but needs a backend.

**GitHub Actions + GHCR**, mainly because the OIDC token is what makes cosign
keyless signing work at all.

**ArgoCD** so CI holds no cluster credentials. The pipeline commits a digest and
stops.

## Running it

```bash
# Task 1 - hardened workload
cd task-1-workload-hardening
./scripts/deploy.sh
./scripts/verify.sh                                    # 17 passed, 0 failed

# Task 2 - pipeline gates + GitOps
./task-2-cicd-supply-chain/scripts/verify-gates.sh     # scanners + negative tests
./task-2-cicd-supply-chain/scripts/finish-gitops.sh    # ArgoCD + drift demo

# Task 3 - Istio mesh (needs Task 1 running first)
cd ../task-3-service-mesh-zero-trust
./scripts/restore-baseline.sh                          # reporting + 2 replicas
./scripts/install-istio.sh                             # istioctl + CNI path guard + inject
kubectl apply -f istio/ -f networkpolicy/
./scripts/verify-mesh.sh                               # mTLS + authz assertions

# Task 4 - local pentest of the bundled vulnerable app (authorised target)
cd ../task-4-recon-pentest
./scripts/recon-passive.sh                             # Part A: passive OSINT
./scripts/pentest-all.sh                               # Part B: build target, exploit, evidence
```

Needs Docker, k3d, kubectl, kubeseal, istioctl. The scripts find their own tool
paths. Task 4's recon needs outbound network for CT logs / DNS.

## Decisions I'd expect to be asked about

**The app's vulnerabilities are still there.** `app.py` has `yaml.load` RCE on
`/import`, SSRF on `/fetch`, cleartext PANs on `/transactions`. That's Task 4's
target. Task 1 contains them instead: RCE lands as uid 10001 on a read-only
filesystem with no capabilities and no ServiceAccount token.

**No RBAC persona, admin included, can read Secrets or exec into a pod.** Sealing
secrets in git is pointless if a developer can just read the decrypted value out
of the cluster. Admins manage SealedSecrets; exec sits in a break-glass Role
bound to nobody.

**The CVE gate blocks on fixable and warns on unfixed.** 182 CRITICAL/HIGH on
this image, 149 fixable, 33 not. Blocking on the 33 leaves the pipeline
permanently red with no action that turns it green, so it gets switched off and
the 149 start shipping too. The 21 suppressions in `.trivyignore` are listed by
CVE id with owner and review date, not by path, so a new finding in the same
files still breaks the build.

## Environment

7.3 GB laptop, Docker VM gets ~3.7 GB. A few things baked into the scripts as a
result:

- BuildKit can't read through OneDrive reparse points, so build contexts get
  copied to a temp dir first.
- k3d writes `host.docker.internal` into the kubeconfig, which resolves to the
  LAN IP on Windows and times out. Rewritten to loopback, and redone on every
  cluster restart since the API port changes.
- Two concurrent Trivy scans starved the API server. `verify-gates.sh` scans once
  and derives both counts.
- `bash script.sh` from PowerShell gets WSL bash, not Git Bash. Different `$HOME`,
  different mount points. Scripts handle both.

## On AI use

The brief allows it, so: I used Claude Code throughout for drafting manifests
and workflows, and more usefully for running verification loops.

Worth being specific, because the useful part wasn't the generation. Several
real defects only surfaced from running things rather than reading them:

- A `.gitignore` rule (`**/secrets/*.yaml`) that would have excluded the
  SealedSecret from git and silently broken both the deploy and the ArgoCD sync.
- A `.gitleaks.toml` block that re-declared a built-in rule with no `regex`,
  which replaces it with an empty one and turns detection off while still
  reporting green.
- A secrets-gate test fixture that embedded its probe token as a literal, so it
  failed the gate it existed to validate.
- A drift demo that scaled replicas and printed success unconditionally, against
  an Application configured to ignore replica differences. It asserted a control
  was working while the transcript above it showed nothing had happened.

The common thread is that a check reporting green tells you nothing until you've
watched it go red. That's why `verify-gates.sh` plants a known-bad input and the
drift demo computes its result from observed state.

Everything here was run and verified, not just written. The reasoning in each
task README is mine.

## Submission

- [x] Repository public
- [x] Top-level README links each task
- [x] Per-task README with approach, reproduction, verification
- [x] Architecture diagrams (Tasks 1, 2, 3 in their READMEs; system overview in [docs/architecture-overview.md](./docs/architecture-overview.md))
- [x] Evidence captured per task under each `evidence/` directory
- [x] Task 4 report as standalone Markdown ([task-4-recon-pentest/pentest-report.md](./task-4-recon-pentest/pentest-report.md))
- [ ] Screenshots, see [docs/screenshots-guide.md](./docs/screenshots-guide.md)
