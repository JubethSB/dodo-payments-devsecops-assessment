# Task 1: Deploy & Harden the Workload

Takes `ledger-api` from the insecure starter to something I'd be comfortable
putting in front of a PCI audit, and proves the controls actually hold at
runtime instead of just existing in YAML.

`./scripts/verify.sh` runs 17 checks. All 17 pass.

## What was wrong to start with

I read `app-source/` before changing anything. The problems:

| # | Issue | Where |
|---|---|---|
| 1 | Live-format Stripe key and DB password sitting in git | `deploy/deployment.yaml` env block |
| 2 | Container runs as root | No `USER` in the Dockerfile, no `securityContext` |
| 3 | Writable root filesystem | No `readOnlyRootFilesystem` |
| 4 | All default capabilities kept | No `capabilities.drop` |
| 5 | seccomp unconfined | No `seccompProfile` |
| 6 | No resource requests or limits | BestEffort QoS, can starve the node |
| 7 | No probes | Kubernetes can't tell "alive" from "working" |
| 8 | Uses the shared `default` ServiceAccount with its token mounted | No `serviceAccountName` |
| 9 | Nothing stops the next bad manifest | No admission policy |
| 10 | Neighbour is a `curl … sleep infinity` shell | `deploy/neighbour.yaml` |
| 11 | EOL base image, 2018-era dependencies | `python:3.6-slim`, Flask 0.12.2 |

## What I deliberately did not fix

`app.py` has three real vulnerabilities:

- `/import` calls `yaml.load()` with no SafeLoader, so it's RCE
- `/fetch?url=` is an unrestricted SSRF
- `/transactions` returns full PANs in cleartext

I left all three alone. They're the authorised target for Task 4, and patching
them here would delete the thing the pen test is supposed to find.

That's not just a scoping excuse. The hardening below is built to *contain*
those bugs rather than remove them, which is the more realistic posture anyway
since you rarely get to assume the app is clean. If someone gets RCE through
`/import` they land as uid 10001 on a read-only filesystem, with every
capability dropped, under seccomp RuntimeDefault, and with no ServiceAccount
token to pivot to the API server with. Task 4 maps each finding back to
whichever control blunts it.

## Design decisions

### The neighbour service

The task wants a neighbour with a Deployment, Service and ConfigMap. The
starter shipped a `reporting` pod that was just curl sleeping forever, with no
Service and no purpose beyond being a shell inside the PCI namespace.

I replaced it with something real: it calls `ledger-api` and serves an
aggregated `/summary`. Same hardening as the main service. It also demonstrates
data minimisation, because `ledger-api` hands out full PANs but `reporting`
aggregates by currency and status and never propagates a `pan` field. Check 10
verifies that. Keeping PANs out of `reporting` keeps it outside CDE scope,
which is the boundary Task 3 draws with the mesh.

The bare curl client comes back in Task 3 as the unauthorised caller for the
AuthorizationPolicy demo.

### Sealed Secrets over SOPS or External Secrets

SOPS+age needs a private key distributed to every operator and to CI. Sealed
Secrets encrypts to a controller keypair that never leaves the cluster, so
developers only ever need the public cert. Fewer copies of a key means fewer
ways to lose one.

External Secrets is the better answer at real scale, but it needs a backend
like Vault, and this has to run locally for free.

The encrypted SealedSecret is also just a normal manifest, so it commits
cleanly and flows through Task 2's ArgoCD sync without special handling.

The plaintext key is gone. Only ciphertext is committed, and check 7 fails the
build if either leaked literal shows up under `manifests/` again.

One thing worth saying: the starter's `sk_live_…` was in git history, so it's
burned. `seal-secret.sh` seals a placeholder and documents that the real fix is
rotating it at Stripe. Re-encrypting a value that's already public would be
theatre.

### Why both PSS and Kyverno

They fail differently, and that's the point.

Pod Security Standards is compiled into the API server, so it keeps working if
someone deletes the Kyverno webhook. But it's all-or-nothing per namespace,
gives generic error messages, and can't express things like "no `:latest`" or
"must be signed".

Kyverno covers those, gives an error naming the exact rule that failed, and
reports through PolicyReports. But it's an external webhook, so it can be
removed.

Check 8 shows the split concretely. A root container gets caught by PSS before
Kyverno ever sees it. A `:latest` tag, missing resource limits, and a writable
root filesystem all get through PSS and are caught by Kyverno. Delete either
layer and real violations start landing.

### RBAC

Two decisions here I'd defend in a review.

**`ledger-api` gets a ServiceAccount with no Role and no token.** The source
makes zero Kubernetes API calls. It's a Flask app; its config arrives as env
vars the kubelet mounts. So least privilege is genuinely nothing at all.
Handing it a token "just in case" would give an attacker with RCE a credential
to pivot with. `auth can-i --list` returns only the self-review verbs every
identity has, and the token path doesn't exist inside the pod.

**No persona, including admin, can read Secrets or exec into a pod.** Sealing
secrets in git is pointless if any developer can run `kubectl get secret -o
yaml` and read the decrypted value. Admins manage SealedSecrets instead, which
are ciphertext.

I treat `pods/exec` as privileged rather than a debugging convenience, because
a shell runs with the pod's identity and can read every mounted secret, which
routes straight around the Secret rules. Exec lives in a separate
`payments-breakglass-exec` Role that isn't bound to anyone. Granting it is a
deliberate, reviewable act during an incident, not something inherited forever.

> Worth knowing: `kubectl auth can-i create pods/exec` gives a false `yes`,
> because it matches the plain `pods` grant. Use `--subresource=exec`. Both
> forms are in `evidence/03-rbac-least-privilege.txt`.

## Architecture

```
                    Internet / operator laptop
                              |
                    :8080 --> ingress-nginx  (TLS, ssl-redirect,
                              |               nosniff / DENY / no-referrer)
   +--------------------------|--------------------------------------+
   |  namespace: payments     |   PSS restricted (enforce/audit/warn) |
   |                          |   label pci-scope=cde                 |
   |                          v                                       |
   |              +-----------------------+                           |
   |              | Service ledger-api    |  ClusterIP :8080          |
   |              +-----------+-----------+                           |
   |                          v                                       |
   |        +---------------------------------+                       |
   |        | Deployment ledger-api  (x2)     |  <-- SealedSecret     |
   |        |  uid 10001, RO rootfs           |      (ciphertext      |
   |        |  caps drop ALL, seccomp RD      |       in git)         |
   |        |  no SA token, limits + probes   |  <-- ConfigMap        |
   |        +---------------------------------+                       |
   |                          ^                                       |
   |                          | http://ledger-api:8080                |
   |        +-----------------+---------------+                       |
   |        | Deployment reporting  (x1)      |  <-- ConfigMap        |
   |        |  uid 10002, same hardening      |      (no secrets)     |
   |        |  /summary aggregates, no PANs   |                       |
   |        +---------------------------------+                       |
   |             Service reporting is ClusterIP only, not exposed     |
   +------------------------------------------------------------------+

   Every pod CREATE goes through:
     API server -> PSS restricted -> Kyverno webhook -> etcd
```

## Prerequisites

| Tool | Version I used |
|---|---|
| Docker | 29.0.1 (Docker Desktop, WSL2) |
| k3d | 5.9.0 |
| kubectl | 1.34.1 |
| kubeseal | 0.27.1 |

`deploy.sh` installs Sealed Secrets v0.27.1, Kyverno v1.13.4 and ingress-nginx
v1.11.3 into the cluster.

## Running it

```bash
cd task-1-workload-hardening
./scripts/deploy.sh
./scripts/seal-secret.sh
./scripts/verify.sh
```

You have to re-seal on a new cluster. A SealedSecret is encrypted to one
controller keypair, and a fresh cluster generates a new key, so the committed
ciphertext won't decrypt. That's the security property working, not a bug.

To see the guardrail reject the original manifest:

```bash
kubectl apply -f app-source/deploy/deployment.yaml
kubectl get pods -n payments      # nothing, every replica refused
```

## Verification

`./scripts/verify.sh`, 17 passed, 0 failed.

| # | Check |
|---|---|
| 1 | ledger-api has ready replicas |
| 2 | Runs as uid 10001, not root |
| 3 | Write to `/` refused |
| 4 | `/tmp` writable via emptyDir |
| 5 | No ServiceAccount token in the pod |
| 6 | caps dropped, seccomp RuntimeDefault, no privilege escalation |
| 7 | No leaked credential under `manifests/` |
| 8 | Four non-compliant pods rejected (root, `:latest`, no limits, RW rootfs) |
| 9 | Three personas can't read Secrets or exec |
| 10 | `reporting` reaches `ledger-api`; `/summary` has no PANs |

Runtime proof:

```
$ kubectl exec ledger-api-... -- id
uid=10001(ledger) gid=10001(ledger) groups=10001(ledger)

$ kubectl exec ledger-api-... -- sh -c 'echo x > /payload.sh'
sh: 1: cannot create /payload.sh: Read-only file system

$ kubectl exec ledger-api-... -- ls /var/run/secrets/kubernetes.io/serviceaccount/
ls: cannot access '...': No such file or directory
```

And the starter manifest being refused:

```
Warning: would violate PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false, unrestricted capabilities,
  runAsNonRoot != true, seccompProfile

$ kubectl get deploy ledger-api -n payments
NAME         READY   UP-TO-DATE   AVAILABLE
ledger-api   0/3     0            0
```

## Evidence

| File | What it shows |
|---|---|
| `evidence/01-pss-rejects-insecure-deployment.txt` | Starter Deployment refused, 0/3 pods |
| `evidence/02-admission-policies-reject.txt` | Four violation types rejected, PSS vs Kyverno attribution |
| `evidence/03-rbac-least-privilege.txt` | Persona matrix, workload SA has nothing |
| `evidence/04-ingress-tls-headers.txt` | HTTPS 200 through the Ingress with security headers |

## Bonus items

- Persona RBAC for developer / operator / admin, plus an unbound break-glass
  exec Role. No persona can read Secrets or exec.
- PSS `restricted` at the namespace, all three modes, version-pinned.
- The original insecure Deployment being rejected, captured in `evidence/01`.

Extras I added beyond the ask: startup probes, `maxUnavailable: 0` rollouts,
topology spread, the data-minimising neighbour, PCI scope labelling, and a
check that fails the build if a leaked secret literal reappears.

### One judgement call

I originally set the security headers with a `configuration-snippet`
annotation on the Ingress. ingress-nginx rejected it, because snippets have
been disabled by default since v1.9.

I didn't override that. A snippet injects raw nginx directives from a
namespaced object into the shared controller config, so anyone who can create
an Ingress in any namespace can affect how traffic is proxied for other
tenants. That's the issue behind CVE-2021-25742 and CVE-2023-5044. Turning
`allow-snippet-annotations` back on to add three response headers would trade a
real cross-tenant escalation path for a cosmetic win.

The headers are set in the controller's own ConfigMap instead, which only a
cluster admin can edit. Same result, no injection surface.
`evidence/04-ingress-tls-headers.txt` shows all three headers present.

## Known limitations

1. **The base image and dependencies are still ancient.** `python:3.6-slim`,
   Flask 0.12.2, PyYAML 5.1, requests 2.19.1. Upgrading means rewriting the app,
   which kills the Task 4 target. Task 2's Trivy gate flags all of it, and that
   firing is the demonstration that the gate works. The real fix is porting to
   Python 3.12 and Flask 3.x behind gunicorn.

2. **Image signing is `Audit`, not `Enforce`.** Task 1 builds images locally and
   side-loads them, so there's no signature to verify and nothing pushed to a
   registry. Setting `Enforce` would block the workload this task exists to
   deploy. It flips in Task 2 once GHCR has cosign-signed images; the policy
   already points at the GHCR paths.

3. **Images use version tags, not digests.** `ledger-api:0.1.0` should really be
   `@sha256:…`. That comes from CI in Task 2.

4. **No NetworkPolicy.** Deliberate, it's Task 3's scope, layered under the
   mesh policy.

5. **Single-node cluster**, so `topologySpreadConstraints` uses
   `ScheduleAnyway`. On a real cluster that becomes `DoNotSchedule` with a PDB.

6. **`reporting` builds `FROM ledger-api`** to reuse cached layers on a
   memory-constrained machine. In production they'd be independent images from a
   shared digest-pinned base, because chaining them means a ledger-api rebuild
   silently rebuilds reporting.

7. **No CPU limit, only memory.** Intentional. CFS throttling adds tail latency
   on a payments path, and memory is the incompressible resource. I'd revisit
   with real load data.

## Environment notes

Built on a 7.3 GB laptop where Docker's VM gets about 3.7 GB.

kind couldn't create a cluster at all. The node never reached systemd's
multi-user target (`could not find a log line that matches "Reached target
Multi-User System"`), including as a single node. k3d/k3s boots reliably in
about two minutes at that memory, so I switched. The brief allows
kind/k3d/minikube equally.

Two Windows-specific workarounds are baked into `deploy.sh`. BuildKit can't
read through OneDrive reparse points, so build contexts get copied to a temp
dir first. And k3d writes `host.docker.internal` into the kubeconfig, which
resolves to the LAN IP on Windows and times out, so the script rewrites it to
loopback.
