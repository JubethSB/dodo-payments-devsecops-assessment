# Interview Walkthrough — How to Explain This Project

Four scripts, escalating in depth. Practise them out loud. The goal is to sound
like you built it (you did) — specific, calm, honest about trade-offs.

---

## 30-second introduction

> "The brief was a payments microservice — `ledger-api`, handling cardholder
> data — that shipped as a root container with a plaintext Stripe key in git and
> no network policy. I hardened it across four layers: the workload (non-root,
> read-only rootfs, PSS + Kyverno admission, Sealed Secrets), the supply chain
> (a GitHub Actions pipeline that scans, signs with cosign keyless, and deploys
> via Argo CD GitOps), the network (Istio mTLS STRICT with identity-based
> authorization plus a NetworkPolicy underneath), and then I put on the attacker
> hat and pen-tested it, mapping every finding back to the control that stops it.
> All of it verified at runtime on a local k3d cluster."

---

## 2-minute explanation

Start with the *why*, then the four layers, then the punchline.

> "The organising principle is defence in depth against an attacker who's already
> inside — because the app *will* have bugs. My Task 4 pen-test proves it has an
> unauthenticated remote code execution. So every layer assumes the one in front
> of it failed.
>
> **Task 1, the workload:** it runs as uid 10001, read-only root filesystem, all
> Linux capabilities dropped, no ServiceAccount token mounted. Admission is
> double-gated — Pod Security Standards `restricted` in the API server, plus
> Kyverno for the rules PSS can't express, like 'no `:latest`' and 'must be
> signed'. Secrets are Sealed Secrets, so the ciphertext is safe in a public
> repo. And no RBAC persona, admin included, can read a Secret or exec into a pod.
>
> **Task 2, the supply chain:** the pipeline scans with Trivy, Semgrep and
> Gitleaks, builds to GHCR, signs keyless with cosign — no stored key, it uses
> the workflow's OIDC identity via Fulcio and Rekor — and attaches a signed SBOM.
> Then it commits the signed digest and stops. Argo CD pulls it. CI holds no
> cluster credentials, so a compromised runner can propose a change but not
> deploy one.
>
> **Task 3, zero-trust:** Istio mTLS STRICT, so plaintext is refused. A
> default-deny AuthorizationPolicy keyed on SPIFFE workload identity — not IP,
> because IPs recycle. Only the `reporting` service account can call
> `ledger-api`; anything else gets a 403. A Kubernetes NetworkPolicy underneath
> catches what the mesh can't — traffic that never reaches a sidecar.
>
> **Task 4:** I exploited four findings — a 9.8 RCE, an 8.6 SSRF, cleartext PAN
> exposure, and reversible tokenization — then showed how Tasks 1–3 contain each
> one. The RCE, chained to steal secrets and exfiltrate them, becomes an
> unprivileged, network-isolated, contained incident once the hardening and
> egress controls are in front of it."

---

## 5-minute explanation

Same spine, but add the *interesting decisions* — the things that show judgement.

Cover the 2-minute version, then add these four "the interesting part was…" beats:

1. **istio-cni was forced, not chosen.** "Default Istio injection needs
   `NET_ADMIN` to program iptables, but the namespace is PSS `restricted` and
   Kyverno drops all capabilities — so a default install literally can't inject.
   I could've relaxed the namespace, but weakening Task 1's central control to
   make Task 3 easier to install is the wrong trade. istio-cni moves that
   privilege to a node-level DaemonSet, so the app pods stay capability-free. The
   honest cost: the privilege didn't disappear, it moved — to one audited
   component instead of every workload."

2. **The CVE gate blocks on fixable, warns on unfixable.** "The base image has
   ~149 CVEs whose only fix is changing the base. Blocking on those leaves the
   pipeline permanently red, which is how a gate gets switched off. So I block on
   the application dependencies I control and track the EOL base as one
   documented accepted risk — not 149 individual suppressions."

3. **Identity over IP.** "The unauthorised client and the authorised one are in
   the same namespace, on the same node, in the same pod CIDR. No NetworkPolicy
   can tell them apart — at L3/L4 they're identical. Only the mTLS certificate
   can. That's why the AuthorizationPolicy and the NetworkPolicy aren't
   redundant: one is identity-aware but enforced in the pod, the other is
   identity-blind but enforced by the CNI, outside the pod."

4. **I verify by attacking.** "Every control has a runtime proof, and the proofs
   are negative results — plaintext getting `http_code=000`, the unauthorised
   caller getting a 403 with the actual Envoy `rbac_access_denied` log line, the
   insecure Deployment getting rejected at admission. A control you've only
   written is a hypothesis. A control you've watched reject the thing it exists
   to stop is verified."

---

## 10-minute technical walkthrough

Screen-share the repo. Walk it in this order, opening the actual files.

1. **`README.md`** (30s) — the four-task table, the stack-and-why. "One folder
   per task, evidence in each."

2. **Task 1 — `manifests/base/00-namespace.yaml`** → point at the PSS labels and
   `pci-scope: cde`. Then **`20-ledger-api-deployment.yaml`** → the
   `securityContext` block (runAsNonRoot, readOnlyRootFilesystem, drop ALL,
   seccomp), `automountServiceAccountToken: false`, probes, limits. Then
   **`manifests/policy/`** → the four Kyverno policies. Then
   **`evidence/02-admission-policies-reject.txt`** → "here's the insecure
   Deployment being rejected four ways." Then **`rbac/10-persona-roles.yaml`** →
   "no persona can read secrets or exec."

3. **Task 2 — `.github/workflows/ci-cd.yml`** — scroll the job graph. Point at
   the per-job `permissions:` blocks ("least privilege — `update-gitops` is the
   only `contents: write`"), the `sign-and-attest` job (`id-token: write`, cosign
   sign, SBOM attest, and the in-pipeline `cosign verify` with pinned identity),
   and `update-gitops` ("commits a digest, no `kubectl` anywhere"). Then
   **`argocd/application.yaml`** → `selfHeal: true` and the `ignoreDifferences`.

4. **Task 3 — `istio/00-istio-install.yaml`** — the `cni.enabled: true` comment
   block (why istio-cni), the trimmed istiod memory, `REGISTRY_ONLY` egress. Then
   **`10-peer-authentication.yaml`** (STRICT), **`20-authorization-policy.yaml`**
   (empty-spec default-deny + the SPIFFE principal), **`30-unauthorised-client.yaml`**
   (the negative control). Then **`evidence/02` and `03`** → the `http_code=000`
   and the 403 with the Envoy RBAC log. Then **`networkpolicy/00-default-deny.yaml`**
   → "deny ingress AND egress, plus the allows the mesh itself needs."

5. **Task 4 — `pentest-report.md`** — the findings table, then open
   **`evidence/02-finding1-yaml-rce.txt`** → "PyYAML 5.1's FullLoader blocks the
   naive gadget, so this is the CVE-2020-14343 bypass; proved three ways including
   the secret-exfil chain." Then the **retest table** → "each finding mapped to
   the Task 1–3 control that stops it."

6. **Close on judgement** — "The thread through all of it: two layers of almost
   everything, because no single control is trusted alone, and everything proven
   by trying to break it."

---

## The one question you must nail

**"Your Kyverno signature policy is in Audit mode — so unsigned images still
run. Isn't that a hole?"**

> "Yes, as deployed locally it audits rather than enforces, and that's a
> deliberate, documented choice for this environment: the local k3d deploy uses
> locally-built images that aren't cosign-signed, so flipping to Enforce would
> deadlock the demo — nothing would schedule. The pipeline *does* sign the GHCR
> image, and in the GitOps path the policy verifies against that signed digest.
> In production this flips to Enforce cluster-wide the moment every image flows
> through the signing pipeline — it's a one-line change from `Audit` to `Enforce`.
> The honest state is: the mechanism is built and the verification logic is
> correct; enforcement is gated on the whole fleet being signed first, which is
> the standard rollout order for admission signature policies."

If you can deliver that answer calmly, you've shown you understand the difference
between "I ran a tool" and "I understand the rollout consequences of enforcement."
