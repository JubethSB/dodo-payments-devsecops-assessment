# Task 2 — Secure CI/CD & Supply Chain: Engineering Handover

## 1. Objective

Task 1 hardened the *workload*. Task 2 hardens the *path the workload travels* to
get to production. The point: security shouldn't depend on a developer
remembering to scan before they ship. It should be enforced by the pipeline, so
an insecure artifact *can't* reach the cluster.

The problem it solves is **supply-chain trust**. When something runs in
production, three questions have to have answers: *What is this exactly?* (a
specific digest, not a mutable tag), *Where did it come from?* (this workflow, in
this repo — provable, not asserted), and *Has anyone looked at it?* (scanned for
CVEs, secrets, and code flaws, with a stated policy on what blocks). The starter
had none of these.

Dodo included it because a Merchant of Record's biggest modern risk isn't just
their own code — it's the dependency they pulled in, the base image with a known
CVE, the build server someone compromised (SolarWinds, Codecov, the xz backdoor).
PCI-DSS Requirement 6.3/6.5 (secure development, change control) and the whole
SLSA framework exist for exactly this. The real-world risk mitigated: shipping a
backdoored or vulnerable artifact, or a compromised CI runner pushing straight to
prod.

## 2. Initial Problem

- **No scanning.** Nothing checked for hardcoded secrets, vulnerable
  dependencies, or dangerous code patterns before build.
- **No signing / provenance.** An image in the registry was just bytes. You
  couldn't prove it came from your pipeline vs. someone who pushed to GHCR with
  stolen creds.
- **Mutable tags.** Deploying `:latest` (or any tag) means the thing you scanned
  and the thing that runs can differ — a tag can be repointed after review.
- **Push-based deploys (implied).** The naive pattern is CI holding a kubeconfig
  and running `kubectl apply`. That makes every CI runner a direct path into
  production; compromise the runner, own the cluster.

Attack scenarios: a dependency with a known RCE ships because nothing scanned it;
an attacker with GHCR write access pushes a malicious image under your tag and
the cluster pulls it because nothing verifies provenance; a compromised GitHub
Action (a supply-chain attack on the CI itself) uses the runner's kubeconfig to
deploy a cryptominer.

## 3. Design Decisions

**GitHub Actions + GHCR.** Free, no cloud account (brief requirement), but the
real reason is **OIDC**. GitHub Actions can mint a short-lived OIDC token
describing the workflow, and that token is what makes cosign *keyless* signing
possible. No other free option gives you keyless signing this cleanly.

**Four scanners, each owning one concern.** One gate per problem so a green run
means something specific:
- *gitleaks* → secrets. Fast (~20s), runs first as the cheap gate.
- *Semgrep* → SAST (dangerous code patterns).
- *Trivy fs* → dependency/CVE scan of the code tree.
- *Trivy image* → CVE scan of the built image (base + installed packages).

*Why not Grype instead of Trivy?* Trivy does fs + image + secret + misconfig in
one tool with good SARIF output; fewer tools, less config drift. Grype is fine;
this is a "one good tool" call. *Why Semgrep and not CodeQL?* Semgrep OSS is free
and fast on this size repo; CodeQL is excellent but heavier. Both upload SARIF.

**Cosign keyless (Fulcio + Rekor), not a long-lived key.** A signing key you
store is a signing key you can leak. Keyless trades the OIDC token for a
short-lived (~10 min) certificate from Fulcio, signs, and logs the signature to
Rekor (a public transparency log). There's no key at rest to steal. The signature
proves *"this came from this workflow in this repo"* — and I pin **both** the
certificate identity regex and the OIDC issuer on verify, because "signed by
somebody" is worthless when anyone can get a Fulcio cert.

**SLSA-style provenance + SBOM attestation.** Beyond the signature, the pipeline
generates an SPDX SBOM and attaches it as a **signed attestation** (cosign
attest). So you can prove not just *who built it* but *what's in it*, and that the
bill of materials itself came from the pipeline.

**GitOps with ArgoCD — pull, not push.** This is the decision I'd defend hardest.
The pipeline **never runs `kubectl apply`**. It commits the new signed digest to a
git path and stops. ArgoCD, running *in* the cluster, pulls that git state and
reconciles. Consequences:
- CI holds **no cluster credentials**. A compromised runner can propose a change
  (a commit) but can't make one (a deploy).
- "What's deployed?" becomes a question about a git commit, not an interrogation
  of the cluster — which is what PCI change-control (who changed what, when, who
  approved) actually needs.
- Drift becomes *detectable*, because there's a declared source of truth to
  compare against.

**Fail policy, stated explicitly** (the brief asks for this): the CVE gate
**blocks on fixable CRITICAL/HIGH in application dependencies** (the things I
control via `requirements.txt`) and **warns, doesn't block, on the EOL base
image's OS packages** (149 fixable-only-by-changing-base findings). Blocking on
those would leave the pipeline permanently red with no action that turns it
green — which is precisely how a gate ends up switched off. The EOL base is
tracked as one accepted risk in `.trivyignore` (by CVE id, with owner and review
date), not padded with 149 individual suppressions. A CVE with no fix at all →
warn and track, because blocking on the unfixable helps no one.

## 4. Implementation Walkthrough

The pipeline is [`.github/workflows/ci-cd.yml`](../../.github/workflows/ci-cd.yml).
Job graph:

```
gitleaks ─┐
semgrep  ─┼─> build ─> image-scan ─> sign-and-attest ─> update-gitops
trivy-fs ─┘
```

Scans run **before** build deliberately — no point attesting provenance for an
artifact nobody has looked at.

- **`gitleaks`** — runs the gitleaks container against the repo with
  `.gitleaks.toml`. Path-scoped allowlists (starter app, sealed ciphertext,
  Task 4 pentest artifacts) with documented reasons; never rule-disabling.
- **`sast` (Semgrep)** — full-repo scan → `semgrep.sarif` uploaded to the
  Security tab (visible), then a **blocking** step that scans again with
  `--severity=ERROR --error`, excluding the deliberately-vulnerable starter app,
  the sealed ciphertext, and Task 4's exploit tree. The full scan reports
  everything; the blocking step decides what stops the build. Remove the
  exclusions and the pipeline blocks forever on vulnerabilities that are the
  *authorised target* of Task 4.
- **`build`** — logs in to GHCR, builds, pushes by digest, emits the digest as a
  job output so downstream jobs pin the *exact* artifact. BuildKit also attaches
  its own SBOM/provenance at push.
- **`image-scan` (Trivy)** — SARIF upload, then the split block/warn policy above.
- **`sign-and-attest`** — needs `id-token: write` (mints the OIDC token). `cosign
  sign` by digest; `anchore/sbom-action` generates SPDX; `cosign attest` attaches
  it; **`cosign verify` and `verify-attestation` with pinned identity+issuer** run
  in the pipeline itself and the output is uploaded as evidence. Runs only on
  non-PR events (you sign what merged, not what's proposed).
- **`update-gitops`** — the *only* job with `contents: write`. `sed`s the new
  `image: …@sha256:<digest>` into the gitops manifest and commits. Digest, not
  tag — the exact thing that was scanned and signed. No `kubectl` anywhere.

ArgoCD side: [`argocd/application.yaml`](../../task-2-cicd-supply-chain/argocd/application.yaml)
with `automated: { prune: true, selfHeal: true }`. `selfHeal` is what turns a
manual `kubectl edit` into a temporary condition instead of a permanent
undocumented change — it's what makes the drift demo possible.
`ignoreDifferences` on `/spec/replicas` (owned by an HPA) and the Secret's
`/data` (written by Sealed Secrets, intentionally not in git).

## 5. Deep Technical Explanation (interview language)

**GitHub Actions** — CI/CD runners triggered by repo events. Jobs run on
ephemeral VMs; permissions are scoped per-job via the `permissions:` block (least
privilege for the token).

**GitOps** — declare desired cluster state in git; an in-cluster agent reconciles
reality to match. Git is the source of truth and the audit log. Pull-based, so CI
doesn't touch the cluster.

**ArgoCD** — the GitOps agent. Watches a git path, diffs it against live state,
and (with automation on) syncs + self-heals. Drift = live state diverging from
git; ArgoCD detects and reverts it.

**Trivy** — a scanner for CVEs (in OS packages and language deps), secrets, and
IaC misconfig. We use fs mode (scan the code tree) and image mode (scan the built
container).

**Semgrep** — SAST: pattern-matches source for dangerous constructs
(`yaml.load`, SSRF sinks, command injection). Rules are readable YAML/patterns.

**gitleaks** — a secrets scanner: regex + entropy over the repo and its history
to catch committed keys/tokens.

**Cosign** — signs and verifies container images (and attestations). Signatures
are stored in the registry alongside the image.

**Fulcio** — Sigstore's certificate authority. It takes your OIDC identity and
issues a **short-lived** signing certificate. This is what makes "keyless" work —
the cert *is* your identity, and it expires in minutes.

**Rekor** — Sigstore's public **transparency log**. Every signature is recorded
immutably, so a signature can be independently verified and its existence proven
later (tamper-evidence).

**SBOM** — Software Bill of Materials: a machine-readable list of everything in
the artifact (packages, versions, licences). We emit SPDX. It's what lets you
answer "are we affected by CVE-X?" across a fleet in minutes.

**SLSA** — Supply-chain Levels for Software Artifacts: a framework for build
integrity. "Provenance" is the signed statement of *how and where* an artifact
was built. Signing + attesting the SBOM moves you up the SLSA levels.

**Provenance** — the verifiable record of an artifact's origin: which source
commit, which builder, which workflow. The cosign attestation carries it.

## 6. Verification

Two layers, both real:

- **In-pipeline:** the `sign-and-attest` job runs `cosign verify` and
  `cosign verify-attestation` itself, with identity + issuer pinned, and uploads
  the output as `cosign-verify.txt`. So every run proves its own signature.
- **Locally:** [`scripts/verify-gates.sh`](../../task-2-cicd-supply-chain/scripts/verify-gates.sh)
  runs the scanners **and a negative test** — it plants a known-bad input and
  confirms the gate goes red. That last part matters more than it sounds: a
  secrets scanner that reports nothing looks identical whether it's working
  perfectly or switched off. Green only means something once you've proven the
  gate *can* go red.

Evidence: [`evidence/03-supply-chain-signing.txt`](../../task-2-cicd-supply-chain/evidence/03-supply-chain-signing.txt)
(cosign verify output), `04-sarif-security-tab.txt` (SARIF surfaced),
`05-argocd-drift-selfheal.txt` (a manual `kubectl edit` reverted by ArgoCD).
Final audit: all 7 pipeline jobs green.

The drift demo is the ArgoCD proof: change a field ArgoCD *watches* (not
`/spec/replicas`, which is in `ignoreDifferences`), and watch self-heal put it
back. My first version of that demo edited replicas and printed success
unconditionally against an Application configured to ignore replicas — it claimed
a control worked while proving nothing. Fixed to edit a watched field and assert
the revert from observed state.

## 7. Problems Faced

**gitleaks reported green while misconfigured.** An early `.gitleaks.toml`
re-declared the built-in `generic-api-key` rule to attach an allowlist. A
`[[rules]]` block *defines* a rule, so declaring an existing id with no `regex`
replaced the built-in with an empty one — detection silently off, still green.
Root cause: misunderstanding gitleaks config semantics. Fix: put every exception
in the single top-level `[allowlist]`, leaving built-in rules intact. Lesson: this
is why `verify-gates.sh` plants a known-bad token every run.

**The negative test "failed" because the fake secret was too famous.** My first
probe token was `sk_live_51NqPzY...` and `AKIA…EXAMPLEKEY` — well-known
documentation values gitleaks ignores by design, so it reported "no leaks" and I
thought the config was broken. It wasn't. Fix: probe with a real-shaped `ghp_…`
token, which is detected immediately. Lesson: validate a gate with an input the
scanner actually treats as live.

**Semgrep SARIF vs. exit code.** The full-repo scan needs `|| true` so a finding
still uploads its SARIF; the *blocking* step is separate. Getting these mixed up
either fails to upload evidence or fails to block. Kept them as two distinct
steps with distinct intent.

**Semgrep blocked on the SealedSecret ciphertext.** `detected-generic-api-key`
fired on the `STRIPE_API_KEY` field of the SealedSecret (matches the field name,
then entropy — and RSA ciphertext is high-entropy by construction). It's a true
false positive: ciphertext isn't a cleartext key. Fixed with a path-scoped
exclusion on the blocking step, full scan still reporting it. Same pattern later
reused for Task 4's intentional fake secrets.

**Two concurrent Trivy scans starved the apiserver.** On the 3.7 GB VM, running
image + fs scans in parallel spiked memory and the local apiserver became
unreachable mid-run. Fix: `verify-gates.sh` scans once and derives both counts.
Lesson: the constraint isn't the tool, it's the box.

## 8. Interview Questions

1. **Why keyless signing over a stored key?** *Short:* no key at rest to leak.
   *Deep:* Fulcio issues a ~10-min cert from your OIDC identity; you sign, Rekor
   logs it, the cert expires. The signature encodes *which workflow in which
   repo* signed, which is stronger than "signed by a key someone holds."
   *Follow-up: what stops anyone signing? → nothing stops signing; verification
   pins identity+issuer, so a signature from a different workflow fails.*

2. **Why pull-based GitOps instead of `kubectl apply` from CI?** *Short:* CI
   holds no cluster creds. *Deep:* push-based makes every runner a path to prod;
   pull-based means a compromised runner can commit (propose) but not deploy
   (act). Also gives you a git-based audit trail for change control. *Follow-up:
   how does a deploy happen then? → ArgoCD reconciles the committed digest.*

3. **A CVE has no fix. What do you do?** *Short:* warn and track, don't block.
   *Deep:* blocking on the unfixable leaves the pipeline red with no path to
   green, so it gets disabled and *everything* ships. I block on fixable app
   deps, track the EOL base as one documented accepted risk with a remediation
   plan (change base image). *Follow-up: isn't that accepting risk? → yes,
   explicitly and with an owner, which is honest; pretending it's clean is not.*

4. **Digest vs tag in the deploy manifest — why?** *Short:* a tag is mutable, a
   digest is the exact bytes. *Deep:* you scan and sign a specific digest; if you
   deploy a tag, someone can repoint it after review and the thing running isn't
   the thing you verified. `update-gitops` pins the digest.

5. **What does the SBOM attestation give you that the signature doesn't?**
   *Short:* *what's in it*, not just *who built it*. *Deep:* the signature proves
   origin; the SBOM lists contents; attesting the SBOM means the bill of
   materials itself is signed, so you can answer "are we exposed to CVE-X" across
   the fleet and trust the answer.

6. **How do you know a green scanner isn't just switched off?** *Short:* a
   negative test that plants a known-bad input every run. *Deep:* `verify-gates.sh`
   proves the gate can go red; I hit exactly the failure where an empty rule and a
   too-famous fake token both produced false green.

7. **Rapid-fire:**
   - *SAST vs DAST?* SAST reads source (Semgrep); DAST attacks the running app
     (Task 4 territory).
   - *Why SARIF?* standard format so findings surface in the GitHub Security tab,
     not just logs.
   - *What's `id-token: write` for?* mints the OIDC token keyless signing needs.
   - *Rekor's job?* immutable public log of signatures — tamper-evidence.
   - *Why scan before build?* don't spend build/sign effort on something nobody
     vetted.

## 9. Design Defence

*"Why ArgoCD and not just a deploy step?"* — because a deploy step needs cluster
credentials in CI, and CI is the fattest target in the whole system (it runs
arbitrary third-party actions). Pull-based removes those credentials entirely.
The cost is one more component to run; the benefit is that a compromised runner
can't deploy. For anything touching cardholder data that trade is obvious.

*"Isn't keyless signing just trusting Sigstore's infrastructure?"* — yes, and
that's a deliberate, well-understood trust anchor (a transparency-log-backed CA)
versus the alternative of trusting that I personally never leaked a private key.
Rekor's public log means signatures are independently auditable. At higher
assurance you can run your own Fulcio/Rekor.

*"Why let the pipeline stay green with 149 CVEs?"* — it doesn't ignore them; it
*reports* all of them to the Security tab and *blocks* on the ones I can fix. The
149 are OS packages in an EOL base whose only fix is changing the base — which is
scheduled and tracked. A gate that's permanently red is a gate people route
around; a gate that blocks on the actionable and documents the rest is one people
keep.

## 10. Real Production Perspective

- **Registry:** GHCR here; ECR/Artifact Registry/ACR in cloud, with image
  immutability and scan-on-push enabled at the registry level too.
- **Signing:** same cosign flow; larger orgs run their own Fulcio/Rekor or use a
  managed Sigstore, and enforce signature verification at admission (which Task
  1's Kyverno `verify-image-signature` policy does — it flips from Audit to
  Enforce once the pipeline publishes signed images).
- **GitOps at scale:** ArgoCD ApplicationSets or Flux across many
  clusters/environments, with progressive delivery (Argo Rollouts) and
  environment promotion via PRs.
- **Policy:** the SLSA provenance gets *verified* at deploy, not just generated —
  admission refuses artifacts without acceptable provenance.
- **Cloud specifics:** OIDC federation to the cloud (GitHub → AWS via IAM OIDC
  provider) so even the build's cloud access is keyless; supply-chain controls
  wired into the org's SIEM. The *pattern* — scan, sign, attest, pull-deploy,
  verify at admission — is identical; the backends and the scale of enforcement
  change.
