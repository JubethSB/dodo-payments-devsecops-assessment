# Executive Summary — Engineering Handover

## What was built

A single PCI-scoped microservice, `ledger-api`, taken from its insecure starter
state (root container, plaintext Stripe key in git, no network policy) to a
defended, production-shaped deployment across four layers, each proven by
attacking it:

1. **Workload hardening** — non-root (uid 10001), read-only root filesystem, all
   Linux capabilities dropped, seccomp `RuntimeDefault`, dedicated
   least-privilege ServiceAccounts with the API token unmounted, secrets moved
   out of git into Sealed Secrets, and admission control (PSS `restricted` + four
   Kyverno policies) that rejects root / `:latest` / unsigned / unhardened pods.
2. **Secure delivery** — a GitHub Actions pipeline that scans (gitleaks, Semgrep,
   Trivy), builds to GHCR, signs keyless with cosign (Fulcio/Rekor), attaches a
   signed SPDX SBOM, and commits the signed digest for ArgoCD to pull — CI never
   touches the cluster.
3. **Zero-trust networking** — Istio with `istio-cni` (so the namespace keeps its
   `restricted` PSS), mTLS `STRICT`, a default-deny `AuthorizationPolicy` keyed on
   SPIFFE workload identity, and a Kubernetes `NetworkPolicy` default-deny
   underneath for defence in depth.
4. **Offensive validation** — passive OSINT of the external surface, then four
   exploited findings on the authorised local target (RCE 9.8, SSRF 8.6, PAN
   exposure 7.5, weak tokenization 5.9), each mapped back to the control from
   layers 1–3 that blunts it.

## Why it was built this way

The organising principle is **defence in depth against an attacker who is already
inside**. Every layer assumes the one in front of it failed:

- The app *will* have bugs (Task 4 proves an unauthenticated RCE), so the workload
  is hardened to shrink what that RCE can do.
- CI *is* a target, so it holds no cluster credentials — it can propose, not
  deploy.
- The network *is not* a trust boundary, so every service call must prove identity
  and pass an explicit allow-list.
- And none of it is believed until it's attacked and the attack is mapped to the
  control that stops it.

Every significant choice has a stated alternative and trade-off (Sealed Secrets vs
Vault, istio-cni vs relaxing PSS, keyless vs stored key, block vs warn on
unfixable CVEs), documented so each is defensible rather than cargo-culted.

## Security improvements delivered

| Before | After |
|---|---|
| Root container | uid 10001, non-root enforced at admission |
| Writable rootfs, all caps | read-only rootfs, all caps dropped, seccomp on |
| Plaintext Stripe key in git | Sealed Secrets ciphertext; no persona can read plaintext |
| Default SA, token mounted | dedicated SAs, token unmounted |
| No admission control | PSS restricted + Kyverno (root/`:latest`/unsigned rejected) |
| No image provenance | cosign keyless signature + signed SBOM, verified in-pipeline |
| Push-based deploy risk | pull-based GitOps; CI has no cluster creds |
| Plaintext east-west traffic | mTLS STRICT, plaintext refused |
| Any pod can call ledger-api | default-deny authz on SPIFFE identity; 403 for others |
| Flat network | NetworkPolicy default-deny + Istio authz, two layers |

## Production readiness

Production-*shaped*, running on a deliberately constrained local environment
(3.7 GB Docker VM, k3d). The patterns transfer directly to a real deployment; what
changes is the backends and the scale of enforcement:

- Sealed Secrets → External Secrets + Vault/cloud secret manager.
- Self-signed istiod CA → istiod as an intermediate under an offline/HSM root.
- Single-node → HA control planes, multi-cluster mesh, ApplicationSets.
- Demo RBAC groups → IdP-federated groups via OIDC; break-glass through PAM.

The security *decisions* — least privilege, default-deny, sign-and-verify,
identity-based authz, defence in depth — are the production ones.

## Remaining limitations (stated honestly)

- **Self-signed istiod root** — the CA key lives in a Kubernetes Secret; a
  cluster compromise forges any mesh identity. Prod fix: intermediate CA under an
  HSM root. (Documented in Task 3 evidence.)
- **EOL base image** — the app's base carries ~149 fixable-only-by-rebase OS CVEs,
  tracked as one accepted risk rather than 149 suppressions; real fix is a
  supported base, scheduled after the pen test.
- **Weak tokenization (Task 4 F4)** — not mitigated by infrastructure; needs a
  real keyed vault in code.
- **crt.sh was down during recon** — bulk CT enumeration was thin; the subdomain
  finding came from the live cert SAN instead.
- **Evidence is text transcripts, not screenshots** — more reproducible, but if a
  reviewer specifically wants screenshots, `docs/screenshots-guide.md` says what to
  capture.
- **Environment fragility** — the local WSL/Docker VM suspends and kills the
  cluster; worked around with continuous-run scripts and restart policies, and
  root-caused in `task-3/evidence/00-environment-triage.txt`. Not a property of the
  design.

## Future improvements

- Migrate secrets to External Secrets + Vault; make istiod an intermediate CA.
- Move the base image to a supported, slim, non-EOL runtime (closes the OS CVEs).
- Enforce cosign signature *verification at admission* (flip Kyverno
  `verify-image-signature` from Audit to Enforce cluster-wide) and verify SLSA
  provenance at deploy.
- Ambient-mode Istio to cut sidecar memory; Argo Rollouts for progressive delivery.
- Wire scanner findings and mesh denials into a SIEM; turn the Task 4
  finding→control mappings into standing policy and detections.
- Real tokenization vault for PANs; authn on every data endpoint.

## Bottom line

Four tasks, every bonus, all verified at runtime with captured evidence, CI green.
The work is defensible decision-by-decision, and the offensive task closes the
loop by proving the defensive work actually contains a real attack. The full
reasoning, the concepts in interview language, the problems hit and how they were
root-caused, and ~20 interview Q&As per task are in the per-task handover docs
alongside this summary.
