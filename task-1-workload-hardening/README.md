# Task 1: Deploy & Harden the Workload

`ledger-api` from the starter repo, deployed and hardened on a local k3d
cluster. `./scripts/verify.sh` runs 17 checks against the running cluster; all
17 pass.

## Starting state

Read through `app-source/` before touching anything. What was wrong:

- Live-format Stripe key and DB password sitting in `deploy/deployment.yaml`
- Runs as root: no `USER` in the Dockerfile, no `securityContext` in the manifest
- Writable root filesystem, all default capabilities, seccomp unconfined
- No resource requests or limits, so BestEffort QoS
- No probes at all
- Uses the namespace `default` ServiceAccount with its token mounted
- Nothing stopping the next bad manifest
- Neighbour is `curlimages/curl` running `sleep infinity`
- `python:3.6-slim` base, dependencies pinned to 2018

## What I left alone

`app.py` has three real bugs: `yaml.load()` with no SafeLoader on `/import`
(RCE), an unrestricted SSRF on `/fetch`, and cleartext PANs on `/transactions`.

All three stay. They're Task 4's target and patching them here deletes the thing
the pen test is meant to find.

The hardening is built to contain them rather than remove them, which is closer
to how this works in practice anyway. RCE through `/import` lands as uid 10001,
read-only filesystem, no capabilities, seccomp on, no ServiceAccount token to
pivot with.

## Decisions worth explaining

**Neighbour service.** The starter's `reporting` pod was curl sleeping forever
with no Service and no purpose. Replaced with something that actually calls
`ledger-api` and serves an aggregated `/summary`, same hardening applied.

It also demonstrates data minimisation: `ledger-api` hands out full PANs,
`reporting` aggregates by currency and status and never propagates a `pan`
field. Check 10 asserts that. Keeps `reporting` outside CDE scope, which is the
boundary Task 3 draws with the mesh.

**Sealed Secrets over SOPS or External Secrets.** SOPS+age needs a private key
on every operator machine and in CI. Sealed Secrets encrypts to a controller
keypair that never leaves the cluster, so developers only need the public cert.
External Secrets is better at real scale but needs a backend like Vault, and
this has to run locally for free.

The starter's `sk_live_` was in git history, so it's burned. `seal-secret.sh`
seals a placeholder and the real fix is rotating at Stripe. Re-encrypting a
value that's already public would be pointless.

**Both PSS and Kyverno.** They fail differently. PSS is compiled into the API
server and survives someone deleting the Kyverno webhook, but it's
all-or-nothing per namespace and can't express "no `:latest`" or "must be
signed". Kyverno covers those and names the failing rule in its error, but it's
an external webhook and can be removed.

Check 8 shows the split: a root container gets caught by PSS before Kyverno sees
it, while `:latest`, missing limits and a writable rootfs all pass PSS and get
caught by Kyverno.

**`ledger-api` gets no Role and no token.** The app makes zero Kubernetes API
calls; config arrives as env vars the kubelet mounts. Least privilege here is
genuinely nothing. Handing it a token "in case" gives an attacker with RCE
something to pivot with. `auth can-i --list` returns only the self-review verbs
every identity has, and the token path doesn't exist in the pod.

**No persona can read Secrets or exec.** Sealing secrets in git is pointless if
any developer can `kubectl get secret -o yaml`. Admins manage SealedSecrets,
which are ciphertext. `pods/exec` is treated as privileged, not a debugging
convenience, since a shell runs with the pod's identity and reads every mounted
secret. Exec lives in `payments-breakglass-exec`, bound to nobody.

Note: `kubectl auth can-i create pods/exec` gives a false `yes` because it
matches the plain `pods` grant. Use `--subresource=exec`.

## Architecture

```
                     :8080 → ingress-nginx (TLS, ssl-redirect,
                              nosniff / DENY / no-referrer)
  ┌──────────────────────────┼───────────────────────────────────┐
  │ namespace payments       │  PSS restricted, label pci-scope=cde
  │                          ▼
  │              Service ledger-api (ClusterIP :8080)
  │                          │
  │         Deployment ledger-api ×2          ← SealedSecret (ciphertext)
  │           uid 10001, RO rootfs            ← ConfigMap
  │           caps drop ALL, seccomp RD
  │           no SA token, limits + probes
  │                          ▲
  │                          │ http://ledger-api:8080
  │         Deployment reporting ×1           ← ConfigMap (no secrets)
  │           uid 10002, same hardening
  │           /summary aggregates, no PANs
  │         Service reporting is ClusterIP only, not exposed
  └───────────────────────────────────────────────────────────────┘

  Every pod CREATE: API server → PSS restricted → Kyverno → etcd
```

## Running it

```bash
cd task-1-workload-hardening
./scripts/deploy.sh
./scripts/seal-secret.sh
./scripts/verify.sh
```

Re-sealing is required on a new cluster. A SealedSecret is encrypted to one
controller keypair, and a fresh cluster generates a new one, so the committed
ciphertext won't decrypt. That's the property working, not a bug — see
`evidence/05-sealedsecret-key-binding.txt`, where exactly this happened during a
rebuild.

To watch the guardrail reject the original manifest:

```bash
kubectl apply -f app-source/deploy/deployment.yaml
kubectl get pods -n payments      # nothing, every replica refused
```

## Verification

17 checks, all passing. Highlights:

```
$ kubectl exec ledger-api-... -- id
uid=10001(ledger) gid=10001(ledger) groups=10001(ledger)

$ kubectl exec ledger-api-... -- sh -c 'echo x > /payload.sh'
sh: 1: cannot create /payload.sh: Read-only file system

$ kubectl exec ledger-api-... -- ls /var/run/secrets/kubernetes.io/serviceaccount/
ls: cannot access '...': No such file or directory
```

The starter manifest being refused:

```
Warning: would violate PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false, unrestricted capabilities,
  runAsNonRoot != true, seccompProfile

NAME         READY   UP-TO-DATE   AVAILABLE
ledger-api   0/3     0            0
```

The rest cover caps/seccomp/priv-esc as applied, no leaked credential under
`manifests/`, four admission rejections (root, `:latest`, no limits, RW rootfs),
three personas unable to read Secrets or exec, and `reporting` reaching
`ledger-api` with no PANs in `/summary`.

## Evidence

| File | Shows |
|---|---|
| `01-pss-rejects-insecure-deployment.txt` | Starter Deployment refused, 0/3 pods |
| `02-admission-policies-reject.txt` | Four violation types, PSS vs Kyverno attribution |
| `03-rbac-least-privilege.txt` | Persona matrix, workload SA has nothing |
| `04-ingress-tls-headers.txt` | HTTPS 200 with security headers |
| `05-sealedsecret-key-binding.txt` | SealedSecret refusing to decrypt on a new cluster |

## Bonus items

Persona RBAC for developer/operator/admin plus an unbound break-glass exec Role.
PSS `restricted` at the namespace, all three modes. The original insecure
Deployment being rejected.

Also added: startup probes, `maxUnavailable: 0` rollouts, topology spread, the
data-minimising neighbour, PCI scope labelling, and a check that fails the build
if a leaked secret literal comes back.

**One thing I decided not to do.** I first set the security headers with a
`configuration-snippet` annotation and ingress-nginx rejected it, since snippets
have been off by default since v1.9. I didn't override it. A snippet injects raw
nginx directives from a namespaced object into the shared controller config, so
anyone who can create an Ingress in any namespace can affect proxying for other
tenants — the issue behind CVE-2021-25742 and CVE-2023-5044. Turning
`allow-snippet-annotations` back on for three response headers isn't a trade
worth making. Headers go in the controller's own ConfigMap instead, which only a
cluster admin can edit.

## Known limitations

**Base image and dependencies are still 2018-era.** Upgrading means rewriting
the app, which kills the Task 4 target. Task 2's Trivy gate flags all of it and
that firing is the point. Real fix is Python 3.12 + Flask 3.x behind gunicorn.

**Image signing is `Audit`, not `Enforce`.** Task 1 builds locally and
side-loads, so there's no signature to verify. Flips in Task 2 once GHCR has
cosign-signed images; the policy already points at the GHCR paths.

**Images use version tags, not digests.** `ledger-api:0.1.0` should be
`@sha256:…`. That comes from CI in Task 2.

**No NetworkPolicy** — deliberate, it's Task 3's scope, layered under the mesh
policy.

**Single node**, so `topologySpreadConstraints` uses `ScheduleAnyway`. On a real
cluster that's `DoNotSchedule` with a PDB.

**`reporting` builds `FROM ledger-api`** to reuse cached layers on a
memory-constrained machine. In production they'd be independent images from a
shared digest-pinned base, since chaining them means a ledger-api rebuild
silently rebuilds reporting.

**No CPU limit, memory only.** CFS throttling adds tail latency on a payments
path and memory is the incompressible resource. Would revisit with real load
data.

## Environment notes

Built on a 7.3 GB laptop where Docker's VM gets about 3.7 GB.

kind couldn't create a cluster at all — the node never reached systemd's
multi-user target (`could not find a log line that matches "Reached target
Multi-User System"`), including single-node. k3d/k3s boots in about two minutes
at that memory. The brief allows either.

Two Windows workarounds in `deploy.sh`: BuildKit can't read through OneDrive
reparse points, so build contexts are copied to a temp dir first; and k3d writes
`host.docker.internal` into the kubeconfig, which resolves to the LAN IP on
Windows and times out, so the script rewrites it to loopback. The k3d API port
also changes on cluster restart, so that rewrite has to be redone rather than
done once.

Scripts resolve their own tool paths. `bash script.sh` from PowerShell gets WSL
bash, not Git Bash, and the two differ in `$HOME`, mount points and environment
— which is why a script that only knew Git Bash reported k3d missing while it
was plainly installed. Note also that a Windows path can't go into `PATH`: it's
colon-separated, so `C:\Users\...` splits at the drive letter and lookups
silently resolve to something unexecutable.
