# Technical Summary — VulnTracker Security Assignment

**Audience:** engineers and reviewers who want the full story
**Reading time:** long-form; this is the detailed companion to
[`executive-summary.md`](./executive-summary.md).

This document walks through how the work was done, from planning to delivery:
the decisions we made, the trade-offs we accepted, and why. It is written in
plain English on purpose.

---

## 1. How we worked (process and tooling)

### Tooling — already available, not installed for this task
All the security tooling we used was **already present in the environment**; we
did **not** install it as part of this assignment: Semgrep (SAST), Trivy
(dependencies, container image, IaC), Gitleaks (secrets), hadolint (Dockerfile
lint), Docker/Colima, Node.js and the GitHub CLI. The **only** thing we added
locally was **Python 3.11 via pyenv**, because the machine did not already have
that version and CI runs on 3.11.

### Models and multi-model validation
The work was done in **Cursor with a private Pro subscription**, which gives
first-party access to Anthropic models — a setup that works well for this kind
of security + coding task. The main model was **Claude Opus 4.8**, which drove
the analysis, the code and the reasoning throughout.

As a deliberate quality step we plan a **second-opinion review (multi-model
validation)** using **Gemini**. The point is not to run the same model twice:
the same family tends to repeat the same blind spots and the same assumptions.
A different model family reviews the findings independently and is more likely
to catch things the first model missed — including its own overconfidence. This
"one model checks the other" approach is a cheap, effective way to raise the
quality of a security review.

### Branching, commits and pull requests
We agreed on clear conventions up front:

- **Branches:** `type/kebab-case`, one branch per task (e.g. `feat/...`,
  `build/...`, `fix/security-remediations`, `docs/task-5-summaries`).
- **Commits:** Conventional Commits (`type(scope): message`).
- **Pull requests:** one PR per task; PR titles follow the same
  Conventional-Commit style (not "Task N: ...").

**Commit strategy — hybrid, and why.** During a task we make **small, focused
commits** (one logical change each) so the work is easy to follow and review.
On merge we normally **squash** into one commit per task, so the main branch
history reads as one clean entry per task / per PR. This gives us the best of
both: a detailed working history on the branch, and a tidy narrative on `main`.

**One deliberate exception — Task 3.** For the remediation task we chose **not**
to squash, because "one commit per finding" (each with its own regression test)
is genuinely more useful to audit than a single squashed blob. The repository
ruleset allows only squash or rebase merges (no merge commits), so we used a
**rebase merge** to land the seven per-fix commits on `main` in order. This is a
conscious, documented deviation from the default squash flow.

### Repository hardening
The repo started **private** and was later switched to **public** (which also
enabled branch protection for free). We set the owner/collaborator to a single
person, added a **ruleset on `main`** so nobody can push directly or force-push,
added a PR template and CODEOWNERS, and normalised `.gitignore` / `.gitattributes`.

---

## 2. Pre-work: reading the code before touching it

Before writing any feature, we read the starter code carefully — specifically
to avoid running or copying something dangerous. That review found the issues
that later became our Task 2 findings and Task 3 fixes: the JWT "none" bypass,
the SQL injection in search, the hardcoded secrets, plaintext password logging,
the IDOR on `GET /scans/{id}`, reflective CORS, the stack-trace-leaking error
handler, and an SSRF path in the notify service. Knowing these in advance shaped
how we built the new feature — we made sure **not to repeat any of them**.

---

## 3. Task 1 — Shared Report Link feature

We added two endpoints: `POST /scans/{scan_id}/share` (create a link) and
`GET /share/{token}` (open it). The link expires after 24 hours and can be
password-protected.

Security decisions in the new code:

- **Owner-only creation.** You can only share a scan you own; others get a
  generic 404. This deliberately does **not** repeat the IDOR bug in the starter
  `GET /scans/{id}`.
- **Token safety.** The token is a 256-bit random value (CSPRNG). We store only
  its **SHA-256 hash**, so a database leak does not reveal working links. SHA-256
  is fine here because the token is already high-entropy and not password-like.
- **Password safety.** Optional password is stored as a **bcrypt hash**, verified
  in constant time, and bounded to 1–64 characters (bcrypt truncates at 72 bytes,
  and a bound also prevents a denial-of-service via huge inputs).
- **Data minimisation.** The public view shows the scan title/description (that
  is the point of sharing) but omits `owner_id` and internal remediation notes.
- **Everything goes through the ORM** — no raw SQL — so we do not reproduce the
  injection pattern.

**One conscious trade-off:** the brief asks for the password on
`GET /share/{token}`, which means it arrives as a `?password=` query parameter.
Query strings can end up in logs, proxies and `Referer` headers (CWE-598). A
hardened design would use a header or a POST body. We accepted the brief's
approach, documented it in the README and in the remediation plan, and reduced
the risk by hashing and never logging the value.

We added eight tests for the feature (create/fetch, password path, invalid token,
expiry, IDOR, auth-required, password-too-long, blank password).

---

## 4. Task 2 — Security analysis and CI pipeline

We ran the four required scan types plus a secrets scan as an independent second
opinion, and saved the raw JSON for each under `reports/`:

| Scan | Tool | Why this tool |
|------|------|---------------|
| SAST | Semgrep (`--config auto`) | Broad Python + JS rules, fast, JSON output. |
| Dependencies (SCA) | Trivy `fs` | One tool covers Python and Node with accurate CVE + fix data. |
| Container image | Trivy `image` | OS packages + libs + secrets + misconfig in one pass. |
| IaC | Trivy `config` | Native Helm/Kubernetes policy checks. |
| Secrets (extra) | Gitleaks | Dedicated secret scanner as an independent check. |

We wrote `docs/findings.md`, which prioritises findings **in the business
context** of VulnTracker (a public share endpoint over sensitive data), not as a
raw copy of CVSS scores.

**We also built these scans into CI as GitHub Actions**, so every push and PR is
scanned automatically. Trivy runs from its official container image rather than a
setup-action, which avoids flaky binary installs on the runner. Each job uploads
its JSON report as an artifact.

**Shift-left:** we run the same scanners **locally before committing and before
merging**, not only in CI. In particular we scan the **Helm chart with Trivy
before the commit and before the PR merges**. CI then re-runs the same gates as a
backstop, so what lands is already clean.

---

## 5. Task 4 — Container and deployment (done before Task 3, on purpose)

**Dockerfile.** Multi-stage build; runs as a **non-root** user (UID 10001);
supports a **read-only root filesystem** (a writable `/data` volume holds the
SQLite file); pinned base image by digest; stdlib **HEALTHCHECK**; no secrets in
the image; `.dockerignore` to keep the build context small.

**Base image — an honest note.** We used `python:3.11-slim`. In production we
would use **Chainguard or Google Distroless** instead: those images ship with
close to zero operating-system CVEs and are hardened by default, which would
remove most of the base-image findings and a lot of manual hardening in one step.
We stayed on `slim` **only** to keep the exercise easy to run and reproduce, and
we say so both in the Dockerfile comment and here.

**Helm chart.** Secure by default: secrets come from a secrets manager via the
**External Secrets Operator** (no secrets in manifests); a **NetworkPolicy**
restricts ingress and limits egress to DNS plus the specific notify pods (not
arbitrary destinations); resource requests/limits; a full **securityContext**
(non-root, read-only rootfs, dropped capabilities, no privilege escalation,
seccomp RuntimeDefault); plus availability best practices (PodDisruptionBudget,
topology spread, rolling updates). Trivy IaC reports **0 misconfigurations**.

**Dependency bumps done here, not in Task 3 — and why.** While building the
image we could already see fixable CVEs in the dependencies. We chose to fix them
**at build time** rather than knowingly build and publish a vulnerable image, and
rather than "introduce" clean dependencies later and risk re-adding the old ones.
The rule we followed was: **drive CRITICALs to zero** (and HIGH where feasible)
now, even where a given CVE may not be directly reachable in our runtime — because
it could still be genuinely risky and the cost of bumping was low. Concretely we
bumped `python-jose` (cleared a **critical** algorithm-confusion CVE),
`cryptography`, `python-multipart`, `fastapi`/`starlette`, `uvicorn` and `httpx`.
Result: Python-layer container CVEs went from **1 CRITICAL / 17 HIGH to 0
CRITICAL / 10 HIGH**, with tests green after every bump. The finer "is this CVE
reachable in *our* runtime?" judgement is what we then separated out in Task 3.

**Supply-chain delay policy.** We deliberately **lag brand-new dependency
releases by 3–7 days** before adopting them. Recent supply-chain attacks
(compromised `axios`-ecosystem releases, the `Shai-Hulud` npm worm, and similar)
are often caught by the community within days, so a short quarantine window
materially lowers the risk of pulling in a poisoned release. This is a documented,
intentional policy — not staleness. It occasionally means holding a fix for a few
days, which we accept as a small, controlled exposure traded against a larger risk.

---

## 6. Task 3 — Remediation

We fixed the top findings in the Python API, one focused commit per fix, each
with a regression test:

| Finding | Fix |
|---------|-----|
| #1 JWT `alg=none` (Critical) | Reject the "none" algorithm; accept only HS256. |
| #2 SQL injection (Critical) | Bound parameter + escaped `LIKE` wildcards. |
| #3 Hardcoded secrets (Critical) | Python + Node secrets from the environment; ephemeral dev key with a warning. |
| #4 Password logging (High) | Log the username only. |
| #6 IDOR on `GET /scans/{id}` (High) | Filter by `owner_id`; uniform 404. |
| #7 Reflective CORS (High) | Allow-list of origins; narrowed headers; preflight handled. |
| #8 Traceback leak (Medium) | Generic 500 body; full detail logged server-side only. |

That is **3 Critical + 3 High/Medium** fixed — more than the brief's minimum —
and the Task 1 feature was already hardened against the same classes, so the "at
least one fix in the new code" requirement is met by design.

After the fixes we **made the SAST and secret CI gates blocking** (they were
report-only earlier, while the starter Critical issues still existed). All gates
are now hard; the full pipeline is green.

`docs/remediation-plan.md` records what was fixed, what was fixed during Task 4,
and the **residual risks we consciously accept** — each with a compensating
control and a named follow-up (notify-service SSRF/axios which is out of code
scope; library HIGHs that need a breaking upgrade or have no patch; base-image
OS CVEs; the `?password=` trade-off; and rotating the secrets that still exist in
git history).

---

## 7. What we would do next (with more time)

- Rotate all previously exposed secrets and confirm production reads them from
  the secrets manager.
- Harden the notify service: SSRF allow-list, authentication on `/notify`, login
  rate-limiting, and an axios/express upgrade (under the 3–7 day policy).
- Move the production image to Chainguard/Distroless.
- Complete the multi-model second-opinion review with Gemini and fold any new
  findings back into the plan.
- Plan the breaking FastAPI upgrade that clears the remaining `starlette` HIGHs.

---

## 8. Summary of key decisions

- **Read before writing.** We reviewed the starter code for traps first, so the
  new feature avoided repeating any known weakness.
- **Fix-as-you-build for dependencies.** We removed fixable CVEs while building
  the image, prioritising zero CRITICALs, and documented the reachability nuance
  in Task 3.
- **Hybrid commits, with a considered exception.** Small commits on branches,
  squash on merge — except Task 3, where per-finding commits (rebased onto main)
  are more auditable.
- **Shift-left and hard gates.** Same scanners locally and in CI; blocking gates
  once the code was clean.
- **Multi-model validation.** Claude Opus 4.8 for the main work, Gemini for an
  independent second opinion, to reduce single-model blind spots.
- **Honest residual risks.** We document what we did not fix and why, rather than
  claiming everything is solved.
