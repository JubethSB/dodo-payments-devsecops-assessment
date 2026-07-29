# Task 1 — Workload Hardening: Engineering Handover

## 1. Objective

The starter shipped `ledger-api` — a service that touches cardholder data — onto
a shared cluster as a root container, with a plaintext Stripe key in git and no
network policy. Task 1 is "take it from that state to something that would
survive a PCI audit."

The security problem it solves is **blast radius**. `ledger-api` is going to have
bugs (Task 4 proves it has an unauthenticated RCE). The question a hardened
workload answers is: *when* that bug is exploited, what can the attacker do next?
On the starter, the answer is "everything" — they're root, they can write
anywhere, they have a mounted Kubernetes token, and the Stripe key is right there
in the environment. After Task 1, the same RCE lands as a non-root user on a
read-only filesystem with no capabilities and no token to steal.

Dodo included this task because it's the foundation everything else sits on. A
service mesh (Task 3) and a signing pipeline (Task 2) are worthless if the pod
they protect is running as root and can be trivially escaped. In PCI-DSS terms
this task is Requirements 2 (secure configuration), 3 (protect stored data), 6
(secure systems), and 7 (least privilege) at the workload layer.

The real-world risk mitigated: a single application vulnerability becoming a full
host/cluster compromise and a cardholder-data breach.

## 2. Initial Problem

What was wrong, concretely, in the starter:

- **Root container.** No `securityContext`, so the process ran as uid 0. A
  container escape from root is dramatically easier than from an unprivileged
  user, and root inside the container maps to root on the node for anything the
  runtime doesn't isolate.
- **Writable root filesystem.** An attacker with code execution could drop a
  binary, modify the app, or persist.
- **All default capabilities.** The default Docker capability set includes
  `NET_RAW`, which lets a compromised pod forge packets and ARP-spoof its
  neighbours on the pod network.
- **Plaintext secrets in git.** `deploy/deployment.yaml` carried a
  `sk_live_...` Stripe key and a DB password as literal env values. Anyone who
  cloned the repo had the keys.
- **Default ServiceAccount, token auto-mounted.** Every pod got a token for the
  `default` SA at `/var/run/secrets/...`. Steal that token, talk to the API
  server.
- **No admission control.** Nothing stopped the next person deploying an equally
  insecure workload.

Example attack scenario, which is exactly Task 4's chain: hit the YAML-RCE on
`/import`, you're now running as root; read the Stripe key straight out of the
environment; use the mounted SA token to enumerate the cluster; write a
cryptominer or a reverse shell to the writable filesystem for persistence. Every
step of that is blocked or degraded by a control in this task.

## 3. Design Decisions

**k3d (k3s) instead of kind.** Not a security choice — a "this machine has 3.7 GB"
choice. kind's node never reached systemd's multi-user target on this Docker VM;
k3s boots in about two minutes single-node. The brief allows either. Documented
so nobody wonders why the cluster tooling is k3d.

**Sealed Secrets over SOPS+age or External Secrets.** All three get the plaintext
out of git. The deciding factor is where the decryption key lives:
- *SOPS+age* encrypts with a key that operators and CI must both hold. That key
  becomes a new distribution problem — every laptop and runner that needs to
  decrypt is a place it can leak.
- *External Secrets* is the best answer at scale, but it needs a backing store
  (Vault, AWS Secrets Manager). On a local, no-cloud assessment that's a
  dependency I'd be standing up just to demo.
- *Sealed Secrets* encrypts to a keypair whose private half **never leaves the
  cluster**. The controller generates it, and I only ever handle ciphertext. The
  committed `SealedSecret` is safe in a public repo because the only thing that
  can decrypt it is the controller I can't export.

The honest trade: Sealed Secrets binds ciphertext to one cluster's key, so
disaster recovery means backing up that key or re-sealing. I hit exactly this —
see Problems. For a single PCI workload that trade is worth it; at fleet scale
I'd move to External Secrets + a real vault.

**PSS `restricted` AND Kyverno, not one or the other.** They fail differently, so
running both is defence in depth, not redundancy:
- *Pod Security Standards* are built into the API server. They can't be bypassed
  by deleting a webhook, because there's no webhook — it's admission logic in the
  apiserver itself. But PSS only knows its three fixed profiles.
- *Kyverno* is a webhook, so in theory someone with cluster-admin could delete
  it. But it expresses rules PSS can't: "no `:latest` tag", "only images from
  our registry", "images must be cosign-signed".

If I had to pick one I'd keep PSS (unbypassable), but the whole point of the task
is showing you don't have to pick. PSS enforces the baseline the kernel cares
about; Kyverno enforces the supply-chain rules the business cares about.

**Dedicated ServiceAccounts with the token unmounted.** `ledger-api` and
`reporting` each get their own SA (`automountServiceAccountToken: false`).
Neither service talks to the Kubernetes API, so neither needs a token. Every
token a workload doesn't carry is one an attacker can't steal from it.

**RBAC by persona (bonus).** Developer / operator / admin Roles, plus a
break-glass exec Role bound to nobody. The load-bearing decision: **no persona,
admin included, can read Secrets or exec into a pod.** Sealing secrets in git is
pointless if a developer can just `kubectl get secret -o yaml` the decrypted
value out of the running cluster. Admins manage `SealedSecrets` (ciphertext);
the ability to read the plaintext Secret or shell into a pod sits in a Role bound
to no subject, so using it is a deliberate, auditable act.

## 4. Implementation Walkthrough

Everything is driven by [`scripts/deploy.sh`](../../task-1-workload-hardening/scripts/deploy.sh),
idempotent, in this order:

1. **Build two hardened images** (multi-stage, non-root `USER`). `ledger-api`
   runs as uid 10001, `reporting` as uid 10002. The script verifies each image's
   uid is non-zero before proceeding — if a base image regressed to root, the
   build fails loudly rather than deploying a root container.
2. **Create the cluster** (k3d, traefik disabled — Task 1 uses ingress-nginx).
3. **Fix the kubeconfig.** k3d writes `host.docker.internal` as the API server,
   which resolves to the LAN IP on Windows and times out; the script rewrites it
   to `127.0.0.1:<port>`. The port changes on every restart, so this is redone
   each run. Remove this and every `kubectl` call hangs.
4. **Namespace with PSS labels.** [`00-namespace.yaml`](../../task-1-workload-hardening/manifests/base/00-namespace.yaml)
   sets `pod-security.kubernetes.io/enforce: restricted` (plus `audit` and
   `warn`) and a `pci-scope: cde` label. Remove the enforce label and non-conformant
   pods are admitted silently.
5. **Sealed Secrets controller**, then apply the committed `SealedSecret`. The
   controller unseals it into a real `Secret` the Deployment consumes. On a fresh
   cluster this fails until re-sealed (see Problems) — the script detects the
   failure and tells you to run `seal-secret.sh`.
6. **Kyverno**, then the four policies in [`manifests/policy/`](../../task-1-workload-hardening/manifests/policy/):
   `require-non-root`, `disallow-latest-tag`, `require-hardened-securitycontext`
   (drop-ALL caps, read-only rootfs, seccomp, no priv-esc, resource limits), and
   `verify-image-signature` (Audit until Task 2 publishes signed images).
7. **RBAC** ([`rbac/`](../../task-1-workload-hardening/manifests/rbac/)) — the SAs
   and the persona Roles/RoleBindings.
8. **Deploy** `ledger-api` + `reporting` with the full hardened
   `securityContext`, resource requests/limits, and startup/readiness/liveness
   probes on every container.
9. **Ingress-nginx** with security response headers (`X-Content-Type-Options`,
   `X-Frame-Options`, `Referrer-Policy`) set through the **controller's**
   ConfigMap, not a per-Ingress snippet — ingress-nginx rejects snippets by
   default because a namespaced snippet can rewrite proxying for other tenants
   (CVE-2021-25742). Self-signed TLS generated at deploy time, never committed.

The hardened `securityContext` (identical shape on both workloads):
```yaml
securityContext:            # pod-level
  runAsNonRoot: true
  runAsUser: 10001
  seccompProfile: { type: RuntimeDefault }
containers:
- securityContext:          # container-level
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities: { drop: [ALL] }
```
Writable paths are handled with an in-memory `emptyDir` mounted at `/tmp`, so
read-only rootfs doesn't break the app. Remove `readOnlyRootFilesystem` and an
attacker with RCE can persist; remove `drop: [ALL]` and they keep `NET_RAW`.

## 5. Deep Technical Explanation (interview language)

**securityContext** — the pod/container security settings the kubelet passes to
the container runtime. It's how you say "run as this uid", "don't allow setuid
escalation", "mount the root fs read-only". Pod-level applies to all containers;
container-level overrides per container.

**Linux capabilities** — the kernel split root's powers into ~40 discrete
capabilities (`NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`, …). Dropping `ALL` means even
if the process is uid 0 inside the container, it can't do the privileged things
root normally can. We keep none; the app binds a high port so it doesn't even
need `NET_BIND_SERVICE`.

**seccomp** — secure computing mode: a syscall filter. `RuntimeDefault` applies
the container runtime's curated blocklist of dangerous syscalls (like
`keyctl`, `ptrace` in some profiles). Without it (`Unconfined`) the whole syscall
table is reachable, which is most of the kernel attack surface.

**ServiceAccount** — the identity a pod uses to talk to the Kubernetes API. By
default every pod gets one and its token is mounted into the filesystem. We give
each workload its own SA and set `automountServiceAccountToken: false` because
these apps never call the API.

**RBAC** — role-based access control: `Role` (a set of allowed verbs on
resources) bound by a `RoleBinding` to a subject (user, group, or SA). Least
privilege means the Role grants exactly what the subject needs and nothing more —
crucially, no `get secrets` and no `pods/exec`.

**Sealed Secrets** — a controller + a CLI (`kubeseal`). You encrypt a Secret to
the controller's public key producing a `SealedSecret` (safe to commit); the
controller in-cluster decrypts it with the private key (which never leaves) into
a normal Secret. Solves "how do I keep secrets in git" without keeping plaintext
in git.

**Kyverno** — a policy engine that runs as an admission webhook. Policies are
YAML (no new language), can `validate` (reject), `mutate` (patch), or
`generate`. We use it to enforce the supply-chain rules PSS can't express.

**Pod Security Standards** — three built-in profiles (`privileged`, `baseline`,
`restricted`) enforced by the apiserver via namespace labels. `restricted` is the
strictest: non-root, no priv-esc, drop-all-caps, seccomp `RuntimeDefault`,
limited volume types. It's the kernel-level baseline; Kyverno layers policy on
top.

## 6. Verification

Verification is [`scripts/verify.sh`](../../task-1-workload-hardening/scripts/verify.sh),
which I re-ran during the final audit: **17 passed, 0 failed.** It doesn't trust
the manifests — it interrogates the running cluster:

- `exec`s into the pod and checks `id -u` → confirms **uid 10001, not root**.
- tries to write to `/` → **"Read-only file system"**, proving the rootfs mount.
- `ls /var/run/secrets/kubernetes.io/serviceaccount/` → **no such directory**,
  proving the SA token isn't mounted.
- reads the live `securityContext` → caps `["ALL"]` dropped, `readOnlyRootFilesystem=true`,
  `allowPrivilegeEscalation=false`, seccomp `RuntimeDefault`.
- greps `manifests/` for the leaked starter credentials → **absent**; confirms
  the committed secret is `kind: SealedSecret` ciphertext.
- **applies the original insecure Deployment and captures the rejection** — this
  is the bonus, and the most convincing evidence: the admission stack rejects
  root, `:latest`, missing-limits, and writable-rootfs pods. Output in
  [`evidence/02-admission-policies-reject.txt`](../../task-1-workload-hardening/evidence/02-admission-policies-reject.txt).
- proves each persona **cannot** read secrets or exec (`kubectl auth can-i` → no).
- confirms `reporting → ledger-api` works over Service DNS (HTTP 200) and that
  `/summary` contains **no PANs** — data minimisation in action.

Why that proves success: a control you've only written is a hypothesis. A control
you've watched *reject the exact thing it exists to stop* is verified. The
admission-rejection test is the one I'd point an interviewer at first.

## 7. Problems Faced

**SealedSecret won't unseal on a fresh cluster.** After a `--recreate`, applying
the committed `SealedSecret` failed: `no key could decrypt secret`. Root cause:
the ciphertext was sealed to the *previous* cluster's controller keypair, which
was destroyed with the cluster; the new controller generated a new key. This
isn't a bug — it's the security property (ciphertext is useless without that
specific cluster's key). Investigation was reading the controller logs. Solution:
re-seal against the current cluster (`seal-secret.sh`). Lesson: seal *after* the
cluster exists, never before; documented in the repo because I later burned a
full rebuild by getting that order wrong.

**PSS `restricted` + Istio would later collide.** Not a Task 1 bug, but a Task 1
*decision that had consequences*: keeping the namespace at `restricted` meant
Istio's default sidecar injection (which needs `NET_ADMIN`) would be rejected. I
chose not to weaken the namespace, which forced the `istio-cni` decision in Task
3. Right call — you don't undo your hardening to make a tool easier to install.

**ingress-nginx rejected the header snippet.** My first pass set security headers
via a per-Ingress `configuration-snippet` annotation; ingress-nginx v1.9+ refuses
those by default. Root cause: a namespaced snippet injects raw nginx config into
the shared controller, so any tenant could rewrite others' proxying
(CVE-2021-25742). Solution: set headers through the controller's ConfigMap
instead, which only a cluster-admin can touch. Lesson: the "annotation is
convenient" path was convenient because it was insecure.

## 8. Interview Questions

Format: **Q**, short answer, then the deeper version and likely follow-ups.

1. **Why drop all capabilities instead of just the dangerous ones?**
   *Short:* least privilege — start from zero, add back only what's needed.
   *Deep:* the app binds a high port and needs no privileged syscalls, so it
   needs no capabilities at all. Allow-listing (drop ALL, add nothing) is safer
   than block-listing (drop a few) because the default set changes between
   runtimes and you inherit whatever's added later. *Follow-up: what if it needed
   port 80? → add only `NET_BIND_SERVICE`, still not the whole set.*

2. **`readOnlyRootFilesystem` breaks apps that write. How did you handle it?**
   *Short:* mount an in-memory `emptyDir` at `/tmp`.
   *Deep:* the only writable path is a `sizeLimit`-bounded `emptyDir` with
   `medium: Memory`, so writes go to tmpfs, not the image layer or the node disk.
   Everything else is immutable, so RCE can't persist to the filesystem.
   *Follow-up: why memory-backed? → bounded, wiped on restart, never touches the
   node's disk.*

3. **PSS or Kyverno — why both?** *Short:* they fail differently. *Deep:* PSS is
   in the apiserver and unbypassable but only knows three profiles; Kyverno is a
   deletable webhook but expresses registry/tag/signature rules PSS can't. Defence
   in depth. *Follow-up: which survives a compromised cluster-admin? → PSS.*

4. **Your SealedSecret is in a public repo. Isn't that a leak?** *Short:* no,
   it's ciphertext. *Deep:* it's encrypted to a keypair whose private half never
   leaves the cluster; cloning the repo gets you an undecryptable blob. I proved
   it by trying to unseal it on a different cluster — it failed. *Follow-up:
   disaster recovery? → back up the controller key or re-seal from source of
   truth.*

5. **Can your admin persona read the Stripe secret?** *Short:* no. *Deep:* no
   persona, admin included, has `get secrets` or `pods/exec`. Sealing secrets in
   git is pointless if someone can read the decrypted value from the live
   cluster, so I closed that path too. Reading plaintext sits in a break-glass
   Role bound to nobody. *Follow-up: how does an admin rotate a secret then? →
   they manage the SealedSecret ciphertext, not the plaintext.*

6. **How do you prove the hardening actually works, not just that the YAML is
   right?** *Short:* `verify.sh` interrogates the running pod and applies the
   insecure Deployment to watch it get rejected. *Deep:* 17 runtime assertions;
   the admission-rejection one is the money shot because it shows the control
   doing its job on the exact input it exists to stop.

7. **What's the difference between `runAsNonRoot` and `runAsUser: 10001`?**
   *Short:* one asserts non-root, the other pins the uid. *Deep:* `runAsNonRoot`
   makes the kubelet refuse to start the container if the image would run as uid
   0 (defence even if the image regresses); `runAsUser` sets the specific uid.
   Together: "must be non-root, and specifically be 10001."

8. **Why `automountServiceAccountToken: false`?** *Short:* the apps never call the
   K8s API. *Deep:* a mounted token is a credential an attacker with RCE can
   steal to pivot to the apiserver. Neither service needs it, so removing it
   removes a whole escalation path. *Follow-up: what if it did need API access? →
   dedicated SA with a tightly-scoped Role, token mounted, nothing more.*

9. **Rapid-fire breadth** *(short answers):*
   - *seccomp RuntimeDefault vs Unconfined?* runtime's curated syscall blocklist
     vs the whole table exposed.
   - *Why a `pci-scope: cde` namespace label?* declares the blast radius / scope
     boundary explicitly for auditors and for Task 3's mesh boundary.
   - *Why disallow `:latest`?* it's mutable — you can't reproduce or verify what
     actually ran; also breaks rollback.
   - *Why multi-stage builds?* build tools don't ship in the runtime image →
     smaller attack surface, non-root final stage.
   - *What is admission control?* the apiserver gate that validates/mutates
     objects before they're persisted to etcd.

## 9. Design Defence

*"Why not just use PSS and skip Kyverno?"* — PSS can't express "only signed
images from our registry, no `:latest`". Those are the supply-chain controls that
tie Task 1 to Task 2. PSS is the kernel baseline; Kyverno is the business policy.

*"Why Sealed Secrets and not Vault/External Secrets?"* — for one workload on a
local cluster, standing up Vault is more moving parts than the problem needs.
Sealed Secrets keeps the private key in-cluster with zero extra infra. I'd
migrate to External Secrets + Vault at fleet scale, and I can articulate exactly
when: when the operational cost of cluster-bound ciphertext (re-sealing on DR)
exceeds the cost of running a vault.

*"Root inside a container is namespaced anyway — why does non-root matter?"* —
user namespaces aren't universally on, several escape techniques need uid 0
inside the container, and the default runtime mapping isn't a guarantee. Non-root
+ drop-all-caps + read-only rootfs is cheap and removes the easy escapes. Depth,
not a single wall.

*"Your admin can't read secrets or exec — isn't that impractical?"* — it's
deliberate friction on the two actions that turn cluster access into data access.
The capability still exists as break-glass; it's just not standing. That's the
difference between "an admin can, if they choose to and it's logged" and "an
admin does, invisibly."

## 10. Real Production Perspective

At a real payments company this is mostly the same *shape*, different *backends*:

- **Secrets:** External Secrets Operator pulling from Vault / AWS Secrets Manager
  / GCP Secret Manager, with dynamic short-lived credentials rather than static
  ones. Sealed Secrets is the local-friendly stand-in.
- **Admission:** Kyverno or OPA Gatekeeper as a fleet policy, distributed via
  GitOps, with policy exceptions themselves reviewed in git.
- **PSS:** enforced cluster-wide via a default namespace label policy, not
  per-namespace by hand.
- **RBAC:** wired to the company IdP (Okta/AzureAD) via OIDC, so "developer" is a
  real group, not a demo string. Break-glass goes through a PAM tool that records
  the session.
- **Cloud specifics:** on EKS you'd add IRSA (IAM Roles for Service Accounts) so
  pods get scoped AWS creds without static keys; on GKE, Workload Identity; on
  AKS, Azure Workload Identity. Node hardening (Bottlerocket/COS) and the managed
  control plane change *where* PSS-equivalents live but not the principle.

What changes at scale is the *distribution and audit* of these controls, not the
controls themselves — which is why getting the shape right locally transfers.
