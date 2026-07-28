# Task 2: Secure CI/CD Pipeline & Supply Chain

Rebuilds the delivery path so the pipeline enforces security instead of relying
on people remembering to. Four gates, keyless signing, SLSA-style provenance,
and GitOps with drift detection.

Pipeline: [`.github/workflows/ci-cd.yml`](../.github/workflows/ci-cd.yml)

**Status: built and locally validated, but not yet executed.** There's no
GitHub remote on this repo yet, so the workflow has never run. See the last
section.

## Pipeline shape

```
  secrets-scan --+
  sast           +--> build --> image-scan --> sign-and-attest --> update-gitops
  deps-scan     -+                                                       |
                                                                         v
                                                            ArgoCD reconciles
                                                              git -> cluster
```

Two ordering choices matter.

The three source-level gates run first and in parallel. None of them needs an
image, so a broken commit fails in about a minute instead of after a multi-minute
container build. Short feedback loops are what keep people actually reading the
output rather than tuning it out.

Signing runs after the image scan, never before. A signature says "this came
from this workflow". Signing something unscanned would attest provenance for a
container nobody has looked at, which is worse than not signing, because it
creates confidence that isn't backed by anything.

## Fail policies

| Gate | Tool | Blocks | Warns |
|---|---|---|---|
| Secrets | gitleaks | Any finding | none |
| SAST | Semgrep | `ERROR` | `WARNING`, `INFO` |
| Dependencies | Trivy (fs) | CRITICAL/HIGH with a fix | Unfixed, MEDIUM/LOW |
| Image | Trivy (image) | CRITICAL/HIGH with a fix | Unfixed, MEDIUM/LOW |
| Signature | Kyverno (Task 1) | Unsigned images | none |

**Secrets are the one gate with no warn mode.** A pushed credential is
exploitable immediately and can't be un-published. Forks, clones and GitHub's
event feed all have it within seconds. There's no "fix it next sprint" for a
live key.

**SAST blocks on ERROR only.** Those are high-confidence, concretely
exploitable patterns, and this codebase produces two of them (the `yaml.load`
sink and the unvalidated `requests.get`). WARNING has a real false-positive
rate, and blocking on it just teaches people to bypass the gate, which is worse
than not having it.

### Handling a CVE with no fix

This is the interesting one. **Block on fixable CRITICAL/HIGH, warn on unfixed.**

Blocking on an unfixed CVE doesn't make anyone safer. There's no patch to
apply, so the only ways back to green are suppressing the finding or not
deploying. Teams under delivery pressure pick suppression, and then the gate is
blind permanently. It also blocks you from shipping fixes for *other*
vulnerabilities, so the net effect is negative.

I measured this on the actual image:

| | Count |
|---|---|
| Total CRITICAL + HIGH | 182 |
| Fixable, so blocks | 149 |
| Unfixed, so warns | 33 |

Those 33 have no fix available anywhere. A block-everything policy leaves this
pipeline permanently red with no action that turns it green, and the gate gets
switched off within a week, at which point the 149 fixable ones start shipping
too.

Unfixed findings don't get ignored, they get triaged outside the pipeline:
check whether the vulnerable path is actually reachable, apply a compensating
control (Task 1's hardening, Task 3's mesh policy), record it against a named
owner with a review date, and keep scanning so it starts blocking the day a fix
lands.

`.trivyignore` has no active suppressions. The EOL base image findings are
deliberately not suppressed, hiding the most significant finding in the repo
to earn a green check would defeat the point of having a scanner.

## Signing and provenance

Cosign keyless, so there's no long-lived signing key to leak:

1. The job asks GitHub for a short-lived OIDC token describing the workflow.
2. Cosign trades it with Fulcio for an ephemeral certificate carrying that
   identity, signs the digest, and logs the entry to Rekor.
3. The private key exists for about ten minutes and is never written down.

It's worth being precise about what a signature does and doesn't claim. It says
the artifact was produced by this workflow from this repo. It says nothing
about whether the image has CVEs. Those are separate questions, which is why
the scan gate exists on its own and runs first.

Verification pins identity, not just "signed". Checking that *somebody* signed
an image is useless, since anyone can get a Fulcio certificate. Both the
pipeline and Task 1's Kyverno policy pin the workflow identity and the OIDC
issuer:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/<owner>/<repo>/\.github/workflows/.+@refs/heads/main$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/<owner>/ledger-api@sha256:<digest>
```

Provenance comes from two places: BuildKit's own `provenance: mode=max` and
`sbom: true` attestations attached at push, plus a Syft SPDX SBOM attached as a
signed `cosign attest` predicate.

## GitOps

The pipeline never runs `kubectl apply`. It commits a digest to git and stops.
ArgoCD pulls.

The security argument is the main one. A push-based pipeline needs a kubeconfig
with write access, which makes every runner a path into production. Here the
pipeline's only privilege is committing to git, so a compromised runner can
propose a change but not make one.

Two other things fall out of it. "What's deployed?" becomes a question you
answer by reading a commit rather than interrogating the cluster, which is what
PCI DSS 6.5 change control actually needs. And drift becomes detectable,
because there's finally something authoritative to compare live state against.

Images are pinned by digest, never tag. The digest is the exact artifact that
passed the scan and carries the signature. A tag can be repointed afterwards,
which invalidates both.

One boundary worth calling out: the GitOps directory holds the ConfigMap,
Service and Deployment only. Namespace, RBAC, SealedSecret and the Kyverno
policies stay with Task 1. If the application pipeline could rewrite the
namespace's PSS labels, then compromising the pipeline would be enough to
disable the guardrails that constrain it. The control and the thing it controls
shouldn't share an owner.

## Architecture

```
   developer push
        |
        v
   +------------------------ GitHub Actions ------------------------+
   |  gitleaks        Semgrep         Trivy fs                      |
   |  (any -> block)  (ERROR -> block) (fixable -> block)           |
   |        +--------------+--------------+                         |
   |                       v                                        |
   |              docker buildx build                               |
   |              + SBOM + provenance                               |
   |                       v                                        |
   |              Trivy image scan --> GHCR                         |
   |                       v                                        |
   |         cosign sign (keyless, OIDC)                            |
   |           +--> Fulcio  (ephemeral cert)                        |
   |           +--> Rekor   (transparency log)                      |
   |                       v                                        |
   |         cosign attest (Syft SPDX SBOM)                         |
   |                       v                                        |
   |         commit digest -> gitops/                               |
   +-----------------------+----------------------------------------+
                           |  no cluster credentials cross this line
                           v
                   +--------------+   watches git
                   |    ArgoCD    |----------------> reconcile
                   +------+-------+   prune + selfHeal
                          v
                 +--------------------+
                 | namespace payments |  Kyverno verifies the cosign
                 |  ledger-api        |  signature at admission
                 +--------------------+
```

## Prerequisites

Docker, kubectl, a public GitHub repo (needed for Actions, GHCR and the OIDC
that makes keyless signing work), and the Task 1 cluster already up so the
`payments` namespace, ServiceAccount and SealedSecret exist.

No cloud account, no paid runners, no signing keys to manage.

## Running it

```bash
# Validate the gates locally, using the same container images CI uses
./task-2-cicd-supply-chain/scripts/verify-gates.sh

# Push, which is what triggers the pipeline
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main

# GitOps
./task-2-cicd-supply-chain/scripts/bootstrap-argocd.sh https://github.com/<you>/<repo>.git
./task-2-cicd-supply-chain/scripts/demo-drift.sh
```

## Verification

`verify-gates.sh` runs the scanners and, more importantly, proves they can
fail:

| Check | What it asserts |
|---|---|
| Clean tree scans clean | No false positives on the committed repo |
| Negative: planted token in an ordinary file | The gate goes red |
| Negative: `sealedsecret`-named file outside `manifests/secrets/` | The allowlist isn't bypassable by filename |
| SealedSecret schema | Allowlisted files really are ciphertext-only |
| Trivy fixable vs unfixed differ | `--ignore-unfixed` is doing real work |

## Evidence

| File | What it shows |
|---|---|
| `evidence/01-trivy-image-scan.txt` | 182 CVEs, the 149/33 split behind the fail policy |
| `evidence/02-gitleaks-gates.txt` | Secrets gate passing clean, plus negative tests proving it can fail |

`evidence/05-argocd-drift-selfheal.txt` gets written by `demo-drift.sh` once
ArgoCD is bootstrapped. Pipeline run links, `cosign verify` output and SARIF
screenshots come after the first push.

## Bonus items

- **SARIF upload.** Semgrep, Trivy fs and Trivy image each upload under their
  own category, so findings land in the repo's Security tab with inline
  annotations instead of sitting in job logs nobody opens.
- **`cosign verify` inside the pipeline.** The workflow verifies its own
  signature and the SBOM attestation and publishes the output as a build
  artifact, so the proof is produced by the run rather than asserted later.
- **Non-root assertion in CI.** The build job runs `id -u` inside the image it
  just built and fails on uid 0. Without it a regression would surface much
  later as a confusing admission rejection from Task 1's policies.

Canary/blue-green isn't done, see below.

## What's not finished

The workflow, ArgoCD manifests and gate configs are written, the YAML is
validated, and the scanners are verified locally against the real image. But
the pipeline itself has never run, because there's no remote configured. Once
pushed it produces the Actions run links, `cosign verify` output, SARIF in the
Security tab and a GHCR package. Nothing else needs changing.

| # | Gap | Notes |
|---|---|---|
| 1 | Pipeline not executed | Needs a public GitHub repo |
| 2 | Kyverno signature policy still `Audit` | Flips to `Enforce` with `mutateDigest: true` once GHCR has signed images |
| 3 | `gitops/` references `ghcr.io/REPLACE_ME/` | Substituted by `bootstrap-argocd.sh`, then rewritten to a real digest by the first run |
| 4 | Manifests duplicated between Task 1 and `gitops/` | Kustomize overlays would fix it; plain manifests keep the ArgoCD demo readable |
| 5 | No canary or blue-green | Argo Rollouts is the natural fit. I'd rather do it alongside Task 3's `VirtualService` traffic splitting, where the mesh handles the weighting |
| 6 | Base image still EOL | Deliberate, see Task 1. Most of the 149 fixable CVEs are base-image packages, so a supported base would take that close to zero |
| 7 | No branch protection | The gates only really bind if `main` requires them to pass. Worth a ruleset requiring all four checks plus review |

## What the first real pipeline run found

Local validation caught a lot, but the first run against GitHub's runners
surfaced three more things that only show up in CI.

**1. `aquasecurity/trivy-action@0.28.0` does not exist.** Valid tags start at
`0.31.0`. The version had never been checked against the upstream release list,
and nothing local catches that because the action is only resolved by Actions
itself. Pinned to `0.35.0`.

**2. `gitleaks-action@v2` fails the job for a reason unrelated to its
findings.** It crashes with `File results.sarif does not exist` while uploading
its artifact, so the gate goes red even when the scan is clean. That is worse
than a broken gate: a check that fails for incidental reasons trains people to
ignore it, and then it is useless on the day it matters.

Replaced with the gitleaks container invoked directly. As a side benefit, CI now
runs the exact command `verify-gates.sh` runs locally, so the two cannot drift.

**3. Semgrep blocked, correctly, and that created a real design problem.**

It found 6 ERROR-severity findings in `app-source/`: the `yaml.load()` without
SafeLoader, the unvalidated `requests.get` SSRF sink, and the cleartext PANs.
The gate did exactly what it should.

The problem is that those findings cannot be fixed. They are the authorised
target for Task 4's penetration test, so removing them deletes the thing the
pen test exists to find. Blocking on them leaves the pipeline permanently red
with no action that turns it green, which is precisely how a gate ends up
switched off.

This is the same shape as the unfixed-CVE question, and it gets the same answer:

- The SARIF scan still covers the **whole repo**, so all 6 findings appear in
  the Security tab.
- The **blocking** step excludes one directory, `app-source/`.
- A separate step prints what the exclusion skipped, so it is a documented
  decision rather than a silent hole.
- New code anywhere else still hard-blocks on ERROR.

The distinction that makes this defensible is that it excludes a **path**, not a
rule and not a severity. Downgrading the rule or dropping the severity
threshold would have made the gate weaker everywhere; excluding one known,
documented directory leaves it at full strength for everything that is actually
under development.

And that turned out to matter, because of what it caught next.

**4. With the starter app excluded, Semgrep found a real vulnerability in the
pipeline itself.**

Two `ERROR` findings remained, both `run-shell-injection` in
`.github/workflows/ci-cd.yml`. My own code. The pattern:

```yaml
run: |
  IMAGE="${REGISTRY}/${IMAGE_NAME}@${{ steps.build.outputs.digest }}"
```

A `${{ }}` expression is substituted by Actions **before bash ever parses the
line**, so it is not a shell variable, it is string interpolation into a script.
Anything attacker-influenced reaching one of those contexts is command
execution on the runner, with whatever the job's token can do. Here that job
holds `packages: write`, and the signing job holds `id-token: write`, which is
the credential that mints signing certificates.

Every affected step now passes the value through `env:` and references it as a
normal shell variable:

```yaml
env:
  DIGEST: ${{ steps.build.outputs.digest }}
run: |
  IMAGE="${REGISTRY}/${IMAGE_NAME}@${DIGEST}"
```

This is the single most useful thing the gate did. The pipeline enforcing the
security controls had a security bug, and the control caught it. It also would
never have surfaced from local validation, because nothing local evaluates
GitHub Actions expression syntax.

**5. A broken scanner config is indistinguishable from a failing gate.**

The gitleaks job failed with `unable to load gitleaks config: toml: array
elements must be separated by commas`. An earlier bulk punctuation edit across
the repo had turned two array separators in `.gitleaks.toml` from `,` into `.`.

gitleaks exits non-zero for a config error and for a real finding alike. In the
Actions UI both are a red X on "Secrets scan", so for one run the secrets gate
had scanned precisely nothing while looking like it was working. `verify-gates.sh`
now parses the TOML before scanning, so a malformed config is reported as a
config error rather than mistaken for a security result.

## Bugs I hit while validating this

I'm listing these because they're the reason `verify-gates.sh` runs negative
tests at all. Every one of them produced a plausible-looking green result, and
none would have been caught by reading the code.

The general problem: a secrets scanner that reports nothing looks exactly the
same whether it's working perfectly or completely switched off. Green only
means something once you've proven the thing can go red.

1. **A malformed allowlist silently disabled a rule.** I tried to attach an
   allowlist by re-declaring the built-in `generic-api-key` rule. A `[[rules]]`
   entry *defines* a rule, so declaring an existing id with no `regex` replaces
   the built-in with an empty one. Exceptions now go in the single top-level
   `[allowlist]`.

2. **The test fixture failed its own gate.** My first `verify-gates.sh` had the
   probe token as a literal, so our own scan flagged the test script twice. It's
   assembled at runtime now.

3. **`set -o pipefail` inverted the negative tests.** This looks fine:

   ```bash
   if gitleaks_scan | grep -q "leaks found"; then ok; else fail; fi
   ```

   gitleaks exits 1 when it finds leaks. Under `pipefail` the pipeline takes
   that 1 instead of grep's 0, so a successfully detected leak was reported as a
   failed test. Capturing to a variable first fixes it, because command
   substitution in an assignment doesn't propagate exit status. Any scanner
   that signals findings through its exit code has this trap.

4. **Path allowlists anchored at the wrong end.** `^task-1-...` never matched,
   because gitleaks reports paths prefixed with the scan root (`/repo/...`).
   Anchor at the end instead.

5. **A Unix path handed to Windows Python.** With `MSYS_NO_PATHCONV=1` set so
   Git Bash stops rewriting container paths, a `/tmp/...` path reaches Windows
   Python verbatim and can't be resolved, so the Trivy count silently produced
   nothing.

6. **Two concurrent Trivy scans starved the cluster.** Running the scan twice,
   once with `--ignore-unfixed`, exhausted the 3.7 GB Docker VM and made the k3d
   API server unreachable mid-run. One scan gives both numbers anyway, since
   "fixable" just means "has a FixedVersion".
