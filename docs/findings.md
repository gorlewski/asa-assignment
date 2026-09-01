# Security Findings — VulnTracker

This document interprets the results of five security scans plus manual review,
and prioritises them **in the business context of VulnTracker** — a service that
stores vulnerability scan results and lets security teams share them with
external stakeholders. That purpose matters: the data is itself sensitive
(it describes where an organisation is weak), and the app deliberately exposes a
**public, unauthenticated** endpoint (`GET /share/{token}`).

## Tooling and why

| Scan type | Tool | Rationale |
| --------- | ---- | --------- |
| SAST | **Semgrep** (`--config auto`) | Broad, multi-language (Python + JS) OWASP/injection ruleset; fast; JSON output. |
| SCA / dependencies | **Trivy** (`fs`) | Single tool covering Python (`requirements*.txt`) and Node (`package-lock.json`); accurate CVE + fixed-version data. |
| Container image | **Trivy** (`image`) | OS packages + language libs + secrets + misconfig in one pass. |
| IaC | **Trivy** (`config`) | Native Helm/K8s policy checks (KSV/AVD); consistent with the rest. |
| Secrets (2nd opinion) | **Gitleaks** | Dedicated secret scanner as an independent check beyond the four required. |

Raw output for each is in `reports/` (`sast.semgrep.json`, `sca.trivy.json`,
`container.trivy.json`, `iac.trivy.json`, `secrets.gitleaks.json`).

## Severity scale

Severity is **our assessment for this application**, not a raw CVSS copy. We
weight: reachability in *this* codebase, exposure (public vs authenticated),
and the sensitivity of what an attacker gains (vulnerability data / account
takeover / lateral movement to the notify service).

---

## Prioritised findings

| # | Finding | Tool / scan | Severity | In starter or new code? | Business impact for VulnTracker |
|---|---------|-------------|----------|-------------------------|---------------------------------|
| 1 | **JWT `alg=none` accepted** — `decode_token` passes `algorithms=[ALGORITHM, "none"]`, so an attacker can forge an unsigned token for any user. | Semgrep (SAST) `jwt-python-none-alg`, `app/auth.py:38`; manual | **Critical** | Starter | Complete authentication bypass. Anyone can impersonate any user, read/modify/delete all scan records and mint share links. For a vulnerability-tracking system this is a full confidentiality + integrity breach of the organisation's weak-spot inventory. |
| 2 | **SQL injection** — `search_scans_by_query` builds SQL via f-string interpolation of user input. | Semgrep (SAST) `avoid-sqlalchemy-text`, `app/database.py:28`; manual | **Critical** | Starter | The search endpoint is authenticated, but any compromised/low-privilege account can dump the entire `scan_results` table across all tenants, or corrupt data. Direct exposure of every customer's vulnerability findings. |
| 3 | **Hardcoded secrets** — `SECRET_KEY`, `DB_PASSWORD`, `ADMIN_API_KEY` in `app/config.py`; `SERVICE_KEY` in `notify/src/config.js`. | Gitleaks; Trivy; manual | **Critical** | Starter | The JWT signing key in source means anyone with repo read (public repo!) can forge valid tokens even after the `alg=none` bug is fixed. The admin API key and DB password enable direct backend access. Secrets in Git persist in history. |
| 4 | **Plaintext password logging** — `login()` logs username **and password** on every attempt and on failure. | Semgrep (SAST) `python-logger-credential-disclosure`, `app/main.py:194,197`; manual | **High** | Starter | Credentials leak into log aggregation, SIEM, disk and backups. A log breach becomes a credential breach; also fails most compliance regimes (PCI/ISO). |
| 5 | **`axios@0.21.1` — 11 known HIGH CVEs** (SSRF CVE-2025-27152, redirect/DoS, credential leakage, etc.). | Trivy (SCA), `notify/package-lock.json` | **High** | Starter | The notify service makes outbound HTTP to registrant-controlled webhook URLs — exactly the SSRF sink these CVEs describe. Combined with finding #9 this is a server-side request forgery pathway into internal networks. Also a live supply-chain concern. |
| 6 | **Broken access control / IDOR on `GET /scans/{id}`** — no `owner_id` filter, unlike list/update/delete. | Manual review | **High** | Starter | Any authenticated user can read any other tenant's scan by iterating integer IDs. Cross-tenant disclosure of vulnerability data. (Our new share feature deliberately does **not** repeat this — it filters by owner.) |
| 7 | **Reflective CORS with credentials** — middleware echoes any `Origin` and sets `Allow-Credentials: true`. | Manual review | **High** | Starter | Any malicious website can make authenticated cross-origin calls in a victim's browser and read the response, enabling data theft / CSRF-style actions against the API. |
| 8 | **Verbose error handler leaks stack traces** — global handler returns `traceback` + exception message in the HTTP 500 body. | Manual review | **Medium** | Starter | Leaks file paths, library versions and internal logic to any caller, accelerating exploitation. The notify service has the same pattern (returns `err.stack`). |
| 9 | **SSRF in notify dispatch** — `dispatch()` POSTs to an arbitrary registrant-supplied `webhook.url` with no allow-list or SSRF guard, and `/notify` is unauthenticated. | Manual review; Semgrep `express-data-exfiltration` (related), `notify/src/index.js` | **High** | Starter | An attacker registers a webhook pointing at `169.254.169.254` or internal services; VulnTracker then makes requests on their behalf, leaking cloud metadata/credentials or reaching internal hosts. Amplified by the vulnerable axios (#5). |
| 10 | **Container OS base CVEs** — `python:3.11-slim` (Debian 13) ships 3 CRITICAL (perl-base) + 13 HIGH OS packages. | Trivy (container) | **Medium** | New (our Dockerfile choice) | Not directly reachable through the app, but enlarges the image attack surface and fails hardened-baseline policies. **A Chainguard/distroless base would bring this to ~zero** (documented in the Dockerfile); we stayed on slim only to keep the exercise reproducible. |
| 11 | **Residual Python lib HIGHs** — `starlette` (3 HIGH; fix needs breaking FastAPI 1.x), `ecdsa` CVE-2024-23342 (no fix), transitive `pyasn1`/`wheel`. | Trivy (SCA / container) | **Medium** | Starter deps (bumped in Task 4) | We already drove Python CRITICALs to zero during Task 4. The remainder need breaking upgrades or have no fix; treated as residual with compensating controls (we use HS256, not ECDSA). See `remediation-plan.md`. |
| 12 | **Node deps `body-parser`/`path-to-regexp` HIGH** — CVE-2024-45590 (DoS), CVE-2024-45296 / CVE-2024-52798 / CVE-2026-4867 (ReDoS). | Trivy (SCA), `notify/package-lock.json` | **Medium** | Starter | DoS against the notify service via crafted input; degrades availability of scan notifications. Notify is out of scope for code changes per the brief, so tracked as residual. |
| 13 | **No authn on `/notify`, no rate limiting on `/auth/login`** — internal trust assumed; login is brute-forceable. | Manual review | **Medium** | Starter | Anyone with network reach can trigger notifications / fan-out; login has no lockout, enabling credential stuffing. |

---

## Findings introduced by our new feature (Task 1)

We reviewed our own Shared Report Link code specifically. SAST produced **no
findings** in it. Two conscious trade-offs are recorded rather than hidden:

| # | Item | Severity | Notes |
|---|------|----------|-------|
| A | **Password passed as `?password=` query string** on `GET /share/{token}` (CWE-598). | Low | Mandated by the brief. Query strings can land in logs/proxies/`Referer`. A hardened design would use a header or POST body. Documented in README. |
| B | Public share projection exposes scan `title`/`description`. | Informational | By design (the feature is "share the scan"). We minimised it: `owner_id` and `remediation_notes` are omitted. |

Our feature also **avoids** repeating starter weaknesses: owner-only creation
(no IDOR), 256-bit CSPRNG token stored only as a hash, bcrypt password with
constant-time verify and a length bound, uniform 404s, server-side expiry.

---

## Already remediated / prevented during earlier tasks

Some findings were fixed **before** this analysis, as a deliberate part of
building a clean container image and a hardened Helm chart. We record them here
so the picture is honest (scan-then-fix vs fix-as-you-build) and so the residual
list is not overstated. Full detail and rationale is in `remediation-plan.md`.

| Area | What we did in Task 4 | Effect on the findings above |
|------|-----------------------|------------------------------|
| **Dependency CVEs (Python)** | Bumped `python-jose` 3.3.0->3.4.0 (**cleared the CRITICAL algorithm-confusion CVE-2024-33663**), `cryptography` ->50.0.0, `python-multipart` ->0.0.30, `fastapi`/`starlette`, `uvicorn`, `httpx`. | Python-layer container CVEs went **CRITICAL 1->0, HIGH 17->10**. We fixed these at build time rather than shipping a knowingly-vulnerable image. The reachability-vs-runtime judgement and residual justification is in `remediation-plan.md`. |
| **Container hardening** | Non-root uid 10001, read-only root FS support, dropped capabilities, stdlib HEALTHCHECK, pinned base by digest, no secrets in image, `.dockerignore`. | Removes whole classes of container misconfig; Trivy config on the Dockerfile = 0. |
| **Deployment hardening (Helm)** | Secrets via External Secrets Operator (no secrets in manifests), restricted ingress + destination-restricted egress NetworkPolicy, resource limits, full securityContext, PDB, topology spread. | Directly addresses the "secrets from a manager / restrict network / limits & contexts" requirements; Trivy IaC = 0 misconfigurations (finding on the IaC scan is clean *because* of this work). |

**Prevention during Task 1 (the two new endpoints).** Building the Shared
Report Link feature was not a remediation of existing findings, but we
deliberately (a) **hardened our own new code** and (b) **avoided reproducing**
starter weaknesses:

- Owner-only share creation with a generic 404 — does **not** repeat the IDOR of
  `GET /scans/{id}` (finding #6).
- All data access via the ORM — does **not** repeat the SQL injection pattern
  (finding #2).
- Our handlers return clean 4xx and never rely on the traceback-leaking global
  handler (finding #8).
- Self-review hardening of the new code itself: password bounded to 1-64 chars
  (bcrypt 72-byte truncation, CWE-521), share-token length guard, whitespace
  password rejected. These prevent *new* issues rather than fixing old ones.

The one deliberate trade-off we introduced (password as a query parameter,
CWE-598) is listed under "Findings introduced by our new feature" above and
carried into `remediation-plan.md`.

**Why bump during Task 4 and not here:** the container scan surfaced fixable
CRITICAL/HIGH CVEs at build time; we did not want to build and publish an image
carrying them. We prioritised driving **CRITICALs to zero** even where a CVE may
not be directly reachable in our runtime, because it could still be genuinely
risky and the cost was low.

**Supply-chain policy:** we deliberately lag brand-new dependency releases by
**3-7 days** before adopting them, to reduce exposure to compromised releases
(recent `axios` ecosystem incidents, the `Shai-Hulud` npm worm, etc.). Pins are
explicit; upgrades are intentional and quarantined.

## Summary counts (raw, from scans)

- **SAST (Semgrep):** 6 findings — 2 ERROR (JWT none, SQLi), 2 WARNING (password logging), 2 in notify (data-exfiltration / CSRF).
- **SCA (Trivy):** Node `axios` 11 HIGH + `body-parser`/`path-to-regexp`; Python `starlette` 3 HIGH residual.
- **Container (Trivy):** OS 3 CRITICAL / 13 HIGH (base image); Python libs 10 HIGH residual; 0 secrets, 0 misconfig in our layers.
- **IaC (Trivy):** **0 misconfigurations** in the Helm chart.
- **Secrets (Gitleaks):** 2 real hardcoded secrets (`app/config.py`, `notify/src/config.js`).

The **top priorities for remediation** are #1 (JWT none), #2 (SQLi) and #3
(hardcoded secrets) — all Critical, all in the starter code, all directly
undermining the confidentiality of the vulnerability data this system exists to
protect. These are addressed in `remediation-plan.md`.
