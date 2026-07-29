# Task 2: Secure CI/CD Pipeline & Supply Chain

Pipeline: [`.github/workflows/ci-cd.yml`](../.github/workflows/ci-cd.yml)

Working end to end. [Run 30419696929](https://github.com/JubethSB/dodo-payments-devsecops-assessment/actions/runs/30419696929)
is green across all seven jobs: image built, scanned, pushed to GHCR, signed
with cosign keyless, SBOM attested, digest committed back to `gitops/`. ArgoCD
picks up that commit and reconciles the cluster.

```
secrets-scan ┐
sast         ├─ build ─ image-scan ─ sign-and-attest ─ update-gitops
deps-scan    ┘                                              │
                                                    ArgoCD reconciles
```

Source gates run first and in parallel since none of them needs an image, so a
bad commit fails in about a minute instead of after a build. Signing runs after
the image scan, not before: signing something unscanned attests provenance for a
container nobody has looked at.

## Gates and fail policy

| Gate | Blocks on | Warns on |
|---|---|---|
| gitleaks | any finding | nothing |
| Semgrep | ERROR | WARNING, INFO |
| Trivy fs | fixable CRITICAL/HIGH | unfixed, MEDIUM/LOW |
| Trivy image | fixable CRITICAL/HIGH in `library` | OS packages, unfixed |
| Kyverno (Task 1) | unsigned images | — |

Secrets get no warn mode. A pushed credential is live the moment it lands and
forks and mirrors have it within seconds, so there is no useful middle ground.

Semgrep blocks on ERROR only. Those findings are high confidence. WARNING has a
false positive rate high enough that blocking on it just teaches people to work
around the gate.

### CVEs with no fix

Block on fixable, warn on unfixed. Blocking on an unfixed CVE gives you two
options, suppress it or stop deploying, and under delivery pressure everyone
picks suppression. Then the gate is blind to the findings that *do* have fixes.

Measured on this image: 182 CRITICAL/HIGH, 149 fixable, 33 unfixed.

Unfixed findings get triaged outside the pipeline. Check whether the vulnerable
path is reachable, apply a compensating control, record it with an owner and a
review date, keep scanning so it starts blocking when a fix ships.

### What is suppressed and why

`.trivyignore` has 21 entries, all listed by CVE id with an owner and a review
date. Twelve are the starter app's pinned dependencies, nine are Python packages
the base image ships (`setuptools`, `wheel`) or pulls in transitively
(`urllib3`).

They are suppressed rather than fixed because upgrading the pins removes Task
4's target, and Flask 0.12.2 / PyYAML 5.1 do not run on a modern interpreter, so
the upgrade is really an application rewrite. CVE-2019-20477, PyYAML command
execution via `python/object/apply`, is the `/import` RCE the pen test goes
after.

Listed by id rather than excluding the path, so these 21 are accepted and a 22nd
still breaks the build.

The image gate blocks on `library` findings and reports OS findings without
blocking. The base contributes roughly 149 fixable OS CVEs whose only real
remediation is a different base image. Listing 149 ids would hide the 150th.

This is accepted risk, not a clean bill of health. A supported base closes both
categories and is the actual fix once the pen test is done.

## Signing

cosign keyless. The job gets a short-lived OIDC token, trades it with Fulcio for
an ephemeral cert, signs, and the entry goes to Rekor. Key lives about ten
minutes and is never written down.

Verified output in `evidence/03-supply-chain-signing.txt`:

```
image     ghcr.io/jubethsb/ledger-api@sha256:63ff99c4...
signed by https://github.com/JubethSB/dodo-payments-devsecops-assessment/
          .github/workflows/ci-cd.yml@refs/heads/main
issuer    https://token.actions.githubusercontent.com
rekor     logIndex 2279152789
```

The Subject line is the part that matters. Anyone can get a Fulcio cert, so
"signed" on its own means nothing. Verification pins the workflow identity and
the issuer, which is what Task 1's Kyverno policy checks at admission.

A signature says nothing about CVEs. That is the scan gate's job, which is why
it is separate and runs first.

Provenance comes from BuildKit's `provenance: mode=max` and `sbom: true`
attestations, plus a Syft SPDX SBOM (135 packages) attached with `cosign attest`.

## GitOps

The pipeline never runs `kubectl apply`. It commits a digest and stops. ArgoCD
pulls.

Main reason is credentials: a push-based pipeline needs a kubeconfig with write
access, which makes every runner a path into the cluster. Here CI can propose a
change but not make one. Secondary benefit is that "what is deployed" becomes a
question you answer by reading a commit.

Images are pinned by digest. The digest is what was scanned and signed; a tag
can be repointed afterwards.

`gitops/` holds the ConfigMap, Service and Deployment only. Namespace, RBAC,
SealedSecret and the Kyverno policies stay with Task 1. If the application
pipeline could rewrite the namespace's PSS labels, compromising the pipeline
would be enough to disable the guardrails constraining it.

Drift demo (`evidence/05-argocd-drift-selfheal.txt`):

```
kubectl set image deploy/ledger-api ledger-api=nginx:1.27-alpine -n payments
  t+1s  OutOfSync detected
  t+4s  image back to ghcr.io/jubethsb/ledger-api@sha256:a778f395...
```

## Running it

```bash
# validate the gates locally, same container images CI uses
./task-2-cicd-supply-chain/scripts/verify-gates.sh

# GitOps against a cluster
./task-2-cicd-supply-chain/scripts/finish-gitops.sh
```

`verify-gates.sh` runs negative tests, not just positive ones: it plants a
detectable token and asserts the scan fails, then checks the SealedSecret
allowlist is not bypassable by filename. A secrets scanner that reports nothing
looks the same whether it is working or switched off.

## Evidence

| File | Contents |
|---|---|
| `01-trivy-image-scan.txt` | 182 CVEs, the fixable/unfixed split behind the policy |
| `02-gitleaks-gates.txt` | clean pass plus the negative tests |
| `03-supply-chain-signing.txt` | verified signature, identity, Rekor index |
| `04-sarif-security-tab.txt` | 100 code scanning alerts, 6 critical, 11 high |
| `05-argocd-drift-selfheal.txt` | drift detected and reverted |

## Notes from getting this working

**`gitleaks-action@v2` fails the job for reasons unrelated to its findings.** It
crashes uploading `results.sarif` even when the scan is clean. Replaced with the
container invoked directly, which is also what `verify-gates.sh` runs locally,
so CI and local testing can't drift.

**A broken scanner config looks exactly like a failing gate.** A bulk edit turned
two array separators in `.gitleaks.toml` from `,` into `.`, so gitleaks exited
with "unable to load gitleaks config" and scanned nothing. In the Actions UI that
is the same red X as a real finding. `verify-gates.sh` parses the TOML before
scanning now.

**Semgrep caught a real injection flaw in the pipeline itself.** Two
`run-shell-injection` findings in `ci-cd.yml`. Expressions like
`${{ steps.build.outputs.digest }}` written inline in a `run:` block are
substituted before bash parses the line, so they are an injection sink, not a
shell variable. Everything goes through `env:` now. The job holding
`id-token: write` is the one that mints signing certificates, so worth fixing
properly rather than suppressing.

**Two scanners owned secrets.** Trivy's `fs` scan runs `vuln + secret + misconfig`
by default and blocked on the starter's `sk_live_` key, which gitleaks already
allowlists with a documented reason. Two tools with different rulesets and no
shared allowlist means every exception gets written twice. Trivy is
`scanners: vuln` everywhere now.

**`concurrency: cancel-in-progress` is wrong for a pipeline that signs.** A run
cancelled between "image pushed" and "image signed" leaves an unsigned image in
the registry, which is the state Kyverno is meant to reject. Removed. If runner
minutes matter later, `cancel-in-progress: false` queues instead of killing.

**A job cannot read its own `needs` output.** A find-and-replace put
`needs.build.outputs.image` into the build job's own metadata step. It resolved
to empty, the tag became bare `main`, and Docker read that as `library/main` on
Docker Hub. The error was `401 insufficient scopes` from `auth.docker.io`, which
looks like a credentials problem and was really a registry nobody meant to use.

**GHCR needs lowercase.** `github.repository_owner` keeps the account's case.
`docker/metadata-action` lowercases it for the tags it generates, so the push
works, but a reference built by hand does not. Computed once in the build job and
published as an output.

**The drift demo was testing the wrong field.** It scaled replicas and printed
success unconditionally. The Application sets `ignoreDifferences` on
`/spec/replicas` so an autoscaler and ArgoCD don't fight, which makes replicas
the one field ArgoCD is told to ignore. The transcript showed replicas sitting at
5 under a line claiming the change had been reverted. It drifts the image now and
computes PASS/FAIL from observed state.

## Not done

- Canary/blue-green. Argo Rollouts is the fit, but it belongs alongside Task 3's
  `VirtualService` traffic splitting where the mesh does the weighting.
- Branch protection. The gates only bind if `main` requires them to pass.
- Base image is still EOL, which is where most of the suppressed CVEs come from.
