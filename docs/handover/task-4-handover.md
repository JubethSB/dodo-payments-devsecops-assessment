# Task 4 — Reconnaissance & Penetration Testing: Engineering Handover

The deliverable is [pentest-report.md](../../task-4-recon-pentest/pentest-report.md).
This handover is the *why and how*, plus interview prep.

## 1. Objective

Tasks 1–3 built defences. Task 4 switches sides and asks: do they hold, and where
would a real attacker get in? Part A maps the external attack surface like an
outsider (passive OSINT). Part B attacks the deliberately-vulnerable app on an
authorised local target and reports findings like a professional pentester.

The problem it solves is **validation without self-deception**. Building controls
and declaring victory is the trap; you only know your hardening works if you
attack it. The bonus — mapping each finding back to the Task 1–3 control that
stops it — is where the whole assessment ties together: it turns four isolated
bugs into a story about defence in depth.

Dodo included it because they want an engineer who can think like an attacker,
scope discipline included (active testing only against the authorised target),
and who scores findings honestly (false positives cost marks). The real-world
risk: shipping something you *believe* is secure because you never tried to break
it.

## 2. Initial Problem

The `ledger-api` app is deliberately vulnerable — it's the assessment's target.
Reading `app.py` (52 lines), the sinks are obvious:
- `yaml.load(request.data)` on `/import` — deserialization RCE.
- `requests.get(url)` on `/fetch` with no validation — SSRF.
- `/transactions` returns full PANs, unauthenticated — data exposure.
- `/tokenize` is `sha256(pan)` — reversible tokenization.
- `STRIPE_API_KEY` / `DB_PASSWORD` read from env — stealable once you have RCE.

Left unchanged in a real deployment, any one of these is a breach; together
they're a full CDE compromise from an unauthenticated HTTP request.

## 3. Design Decisions

**Scope discipline as a first-class decision.** The brief authorises *passive*
recon of `dodopayments.tech` and *active* testing only against the local target.
So Part A touches the domain as little as possible — CT logs (a query to a
third-party database, zero packets to Dodo), DNS, one TLS handshake, one HTTP
banner per host, rate-limited — and runs *no* scanners/fuzzers/exploits against
it. All active work is confined to the local target. Getting this wrong is
"disqualifying" per the brief, so it's designed in, not bolted on.

**Run the real app, pinned to its real dependencies.** The target is built from
the same `app.py` with the *original* pins (Flask 0.12.2, **PyYAML 5.1**, requests
2.19.1), so I'm testing the app as it actually ships, not a convenient rewrite.
This matters — PyYAML 5.1's behaviour is *why* the RCE needed a specific gadget
(below). Bound to loopback only; it's vulnerable by design and must never be
reachable off-host.

**curl PoCs over Burp/ZAP screenshots.** The brief lists Burp/ZAP/nuclei/sqlmap.
For a *reproducible text report*, `curl` request/response transcripts are cleaner
and re-runnable than GUI screenshots, and they're what the evidence files are.
A GUI proxy would add pictures, not findings. Stated as a limitation.

**Honesty over finding count.** SQLi and XSS were *tested for and ruled out* (no
SQL sink — the ledger is an in-memory list; JSON-only responses via `jsonify`, no
HTML sink). Reporting them would be padding, and the brief penalises false
positives. Four real, exploited findings beat eight half-confirmed ones.

**Stand up an internal victim for the SSRF.** To *prove* SSRF reaches internal
services (not just assert it), I ran a second container (`t4-internal`) serving a
mock IAM-credential doc on a private docker network, **published to no host
port**. From the host it's unreachable; through `/fetch` it's retrieved — which is
a concrete, undeniable SSRF proof and doubles as the metadata-credential-theft
scenario.

## 4. Implementation Walkthrough

- **[`scripts/recon-passive.sh`](../../task-4-recon-pentest/scripts/recon-passive.sh)**
  — Part A. crt.sh + certspotter (CT), DNS resolution, one `openssl s_client`
  handshake per host (TLS posture + SAN harvest), one `curl -sI` banner per host.
  Rate-limited, graceful fallback to `curl`/`openssl`/`python` when
  subfinder/httpx/jq aren't installed. Writes `evidence/01`.
- **[`target/Dockerfile`](../../task-4-recon-pentest/target/Dockerfile)** — builds
  the vulnerable app with its pinned deps, plus compatibility pins
  (`markupsafe==1.1.1`, `itsdangerous==0.24`) so 2017-era Flask actually imports.
  Injects fake `STRIPE_API_KEY`/`DB_PASSWORD` so the secret-theft chain has
  something to steal.
- **[`scripts/run-target.sh`](../../task-4-recon-pentest/scripts/run-target.sh)** —
  builds + runs on `127.0.0.1:18080` (18080 because the k3d LB owns 8080).
- **[`scripts/pentest-all.sh`](../../task-4-recon-pentest/scripts/pentest-all.sh)**
  — Part B end to end in one run: private network, internal victim, target, then
  all four findings → `evidence/02..05`.
- **[`scripts/exploit-yaml-rce.sh`](../../task-4-recon-pentest/scripts/exploit-yaml-rce.sh)**
  — Finding 1 in depth: the blocked naive gadget, the working CVE-2020-14343
  gadget, and the secret-exfil chain, proven three ways.

## 5. Deep Technical Explanation (interview language)

**Reconnaissance / OSINT** — gathering information about a target from public
sources without touching it aggressively. Passive OSINT = CT logs, DNS, WHOIS,
public certs. The goal is an attack-surface map before you send a single
suspicious packet.

**Attack surface mapping** — enumerating everything externally reachable
(subdomains, hosts, technologies, TLS posture) so you know where to look. The
highest-value passive source is Certificate Transparency: every TLS cert a public
CA issues is logged, so an org's hostnames leak there — including internal-sounding
ones. On this target the live cert's SAN leaked `squirrels.dodopayments.tech` +
wildcard.

**OWASP Top 10** — the industry's canonical list of web app risk classes: broken
access control, injection, SSRF, security misconfiguration, cryptographic
failures, etc. My four findings map to injection (RCE), SSRF, broken access
control (PAN exposure), and cryptographic failure (tokenization).

**CVSS v3.1** — the standard scoring system. A base vector like
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (network, low complexity, no privileges, no
user interaction, unchanged scope, high C/I/A) computes to 9.8. "Scope changed"
(S:C) means the impact hits something *beyond* the vulnerable component — that's
why SSRF (reaches internal systems) is S:C.

**SSRF** — Server-Side Request Forgery: you control a URL the *server* fetches, so
the server makes requests on your behalf — to internal services, cloud metadata
(`169.254.169.254`), or as a port scanner. The server's network position becomes
yours.

**Deserialization RCE** — turning attacker-controlled serialized data into code
execution. `yaml.load` (pre-safe) constructs arbitrary Python objects; the right
YAML tags call arbitrary functions.

**SQLi / XSS / IDOR** — SQL injection (inject into a DB query), Cross-Site
Scripting (inject script into a page rendered for other users), Insecure Direct
Object Reference (access another user's object by changing an id). All tested-for
here; SQLi/XSS ruled out (no SQL, JSON-only), and there's no multi-user object
model for IDOR.

**Burp Suite / ZAP** — intercepting proxies for manual web testing (inspect,
tamper, replay requests). **nuclei** — template-based vulnerability scanner.
**ffuf** — fast content/parameter fuzzer (directory brute force). **sqlmap** —
automated SQLi exploitation. I used curl for reproducible transcripts; these are
the standard toolkit and I can speak to each.

## 6. Verification

Every finding is a *reproduced exploit*, not a scanner flag, with the real server
response captured:

- **F1 RCE (CVSS 9.8):** three proofs — timing (`sleep(5)` → 5.04s round-trip),
  command output (`id` → `uid=0(root)` in the app's stdout), and the chain (the
  gadget reads `STRIPE_API_KEY`+`DB_PASSWORD` and prints/exfiltrates them:
  `EXFIL_PROOF stripe=sk_live_… db=Sup3rSecret-DB-Pass!`).
- **F2 SSRF (8.6):** `/fetch?url=http://t4-internal/…` returns the internal-only
  IAM doc (`AccessKeyId`, `SecretAccessKey`) the host itself can't reach.
- **F3 PAN (7.5):** `curl /transactions` → full PANs, no auth.
- **F4 tokenization (5.9):** same PAN → same token (deterministic), and a captured
  token reversed to its PAN via a small offline dictionary.

Why these prove success: each is a direct, unambiguous outcome an attacker wants —
a root shell's output, internal credentials in the response, card numbers,
a recovered PAN. There's no interpretation gap.

## 7. Problems Faced

**The RCE that "didn't work" (and why that was the interesting part).** My first
payload — `!!python/object/apply:os.system` — returned HTTP 500, not code
execution. Root cause: the pinned PyYAML is **5.1**, whose `yaml.load()` default
is `FullLoader`, which *blocks* the naive `apply` gadget (`module 'subprocess'
is not imported`). A tester who stopped there would wrongly call `/import` safe.
It isn't: `FullLoader` before 5.4 is defeated by the **CVE-2020-14343**
`type`/`extend`/`exec` gadget. I confirmed it empirically (a marker-file test in
the container) before wiring it into the HTTP PoC. Lesson: *verify the exploit
against the actual pinned version*, and don't trust a 500 as "not vulnerable."

**The `request.data` empty-body trap.** Even with the right gadget, responses came
back `None`. Root cause: `curl --data-binary` with no `Content-Type` defaults to
`application/x-www-form-urlencoded`, so Flask consumed the body into
`request.form` and `request.data` was empty — the sink saw `b''`. Fix: send
`Content-Type: application/x-yaml`. This is a genuine exploitation detail (it turns
a real vuln into a false negative) so it's documented in the evidence.

**2017-era dependency hell.** Flask 0.12.2 / Jinja2 2.10 import
`soft_unicode` from markupsafe, removed in markupsafe 2.1; pip pulled a modern
markupsafe and the app wouldn't start. Fix: `--force-reinstall markupsafe==1.1.1
itsdangerous==0.24` in the Dockerfile. Lesson: pinning the app isn't enough; its
transitive deps drift too.

**Port 8080 already taken.** The target collided with the k3d loadbalancer on
8080. Moved to 18080. Trivial, but the kind of thing that wastes ten minutes if
you don't read the error.

**The security gates flagged my own exploit code.** After committing Task 4,
gitleaks and Semgrep (correctly) flagged the fake `sk_live_` key and the RCE
gadgets. Fix: path-scoped, documented allowlists for the Task 4 tree — the same
treatment the deliberately-vulnerable starter app already gets — on the *blocking*
step only, full scan still reporting. Lesson: an offensive task's artifacts trip
defensive gates by design; handle it explicitly, don't disable the gate.

## 8. Interview Questions

1. **Walk me through the RCE.** *Short:* YAML deserialization on `/import` via a
   FullLoader-bypass gadget → code exec as root. *Deep:* PyYAML 5.1 blocks the
   naive `apply` gadget, so I used CVE-2020-14343's `type/extend/exec`
   construction; proved it three ways (timing, `uid=0`, secret exfil); the
   Content-Type must be non-form or `request.data` is empty. *Follow-up: how do
   you fix it? → `safe_load`, upgrade PyYAML ≥6, schema-validate input.*

2. **Why is your SSRF proof convincing?** *Short:* it reached a service the host
   itself can't. *Deep:* the victim was published to no host port, so retrieving
   it through `/fetch` is unambiguous — the server's network position, not mine.
   Same primitive hits `169.254.169.254` on real cloud. *Follow-up: fix? →
   allow-list scheme/host, block RFC1918/link-local after DNS resolution.*

3. **You scored the RCE 9.8. Defend the vector.** *Short:*
   `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. *Deep:* network-reachable,
   unauthenticated, no interaction, full C/I/A on the component. Scope unchanged
   because it's the app process; if I argued container escape I'd take S:C higher.
   *Follow-up: why not 10.0? → 10.0 needs scope changed with full impact.*

4. **Why did you rule out SQLi instead of running sqlmap anyway?** *Short:* there's
   no SQL. *Deep:* the data is a Python list literal — no query, no sink. Running
   sqlmap would produce a clean "not injectable" that adds noise; reporting a
   non-finding as tested-and-clear is the honest move, and the brief penalises
   false positives. *Follow-up: how do you know there's no hidden DB? → read the
   source; black-box behaviour confirms it (static data, no error-based leakage).*

5. **How does the chain make this worse than the sum of parts?** *Short:* one
   request → code exec → secrets → exfil. *Deep:* F1 alone is RCE; chained with
   env-secret theft and outbound egress it's the Stripe key + DB password + PAN
   ledger leaving the building from a single unauthenticated POST. That's the
   breach vs. bug distinction.

6. **Your bonus maps findings to Tasks 1–3. Give the RCE example.** *Short:*
   hardening + egress controls contain it. *Deep:* Task 1 makes RCE land as uid
   10001 on a read-only fs with no caps and no SA token; Task 3's `REGISTRY_ONLY`
   egress + NetworkPolicy default-deny *block the exfil*. The critical finding
   becomes an unprivileged, network-isolated, contained incident. F4 (tokenization)
   is *not* fixed by infra — stated plainly.

7. **Rapid-fire:**
   - *What's CT and why does it help recon?* Certificate Transparency logs; every
     public cert leaks its hostnames.
   - *Passive vs active recon?* passive doesn't touch the target aggressively;
     active sends probes/exploits.
   - *S:U vs S:C in CVSS?* impact stays in the component vs. crosses a trust
     boundary.
   - *Why loopback-bind the target?* it's vulnerable by design; never expose it.
   - *One remediation for the PAN endpoint?* authn + mask to first6/last4 + data
     minimisation.

## 9. Design Defence

*"You didn't use Burp/nuclei/sqlmap — is this a real pentest?"* — the findings are
real, reproduced, and CVSS-scored; the *evidence format* is curl transcripts
because a text report needs re-runnable proof, not screenshots. I can drive Burp
and speak to when each tool earns its place (nuclei for breadth across many hosts,
sqlmap where there's actually SQL). Choosing the reproducible tool for the
deliverable is the judgement call, not a gap.

*"Only four findings?"* — depth over count is the brief's explicit ask, and false
positives cost. Each finding is exploited end-to-end; I ruled out SQLi/XSS rather
than list them for volume. A report padded with scanner noise is worse than four
proven criticals-to-mediums with clean remediations.

*"Isn't standing up a fake metadata service cheating the SSRF proof?"* — it's the
opposite: it makes the proof *concrete and local* instead of pointing at a cloud
metadata endpoint I can't show. The victim is unreachable from the host, so
reaching it through the app proves the primitive exactly. On real infra the same
request hits `169.254.169.254`.

## 10. Real Production Perspective

- **Recon at scale:** subfinder/amass with API keys, httpx/nuclei across the whole
  discovered surface, continuous ASM (attack-surface management) tooling watching
  CT logs for new hostnames. What I did by hand, a program runs daily.
- **Pentest process:** scoped engagements with rules of engagement, a retest
  cycle, and findings tracked to closure in a system of record — plus the
  *finding→control* mapping I did as the bonus, which is what a mature security
  program uses to prioritise remediation (fix the class, not just the instance).
- **The defensive tie-back is the point:** in a real org, each finding becomes a
  detection rule and a control requirement, not just a ticket. The RCE→exfil chain
  becomes "egress default-deny is mandatory in the CDE" as policy.
- **Cloud specifics:** the SSRF-to-metadata path is why AWS pushes IMDSv2
  (token-required metadata), GCP/Azure have equivalents, and why egress controls
  (SGs, NACLs, egress firewalls, the mesh's `REGISTRY_ONLY`) are non-negotiable
  for cardholder-data workloads. The exact finding I demonstrated locally is the
  one that has caused real cloud breaches (Capital One, 2019).
