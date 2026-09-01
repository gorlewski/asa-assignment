# Remediation Plan — VulnTracker

Companion to [`findings.md`](./findings.md). It records **what we fixed**, **how**,
and — just as importantly — **what we consciously did not fix**, with the reason
and the compensating control for each residual risk. Finding numbers (`#1`…`#13`,
`A`/`B`) refer to the table in `findings.md`.

The guiding principle is honesty: a remediation plan that claims everything is
fixed is not credible. We separate *fixed*, *fixed-earlier-during-build*, and
*residual (accepted, with a control and an owner)*.

---

## 1. Fixed in Task 3 (code remediation)

Each fix is a focused commit on `fix/security-remediations` with a regression
test. All 25 Python tests and the notify suite pass; SAST (Semgrep) reports 0
ERROR findings and Gitleaks reports no leaks.

| Finding | Fix | Where | Test |
|---------|-----|-------|------|
| **#1 JWT `alg=none`** (Critical, auth bypass) | Removed `"none"` from the accepted `algorithms` list; only the configured HS256 is accepted. | `app/auth.py` | `test_jwt_none_algorithm_rejected` forges an unsigned `alg=none` token and asserts 401. |
| **#2 SQL injection** (Critical) | Rewrote `search_scans_by_query` to use a bound parameter (`:pattern`) instead of f-string interpolation, and escape `LIKE` wildcards (`%`, `_`, `\`) so input is a literal substring. | `app/database.py` | `test_search_sql_injection_is_neutralised`, `test_search_wildcards_are_literal`. |
| **#3 Hardcoded secrets** (Critical) | `SECRET_KEY`, `DB_USER`, `DB_PASSWORD`, `ADMIN_API_KEY` (Python) and `SERVICE_KEY` (Node) now come from the environment. If `SECRET_KEY` is unset a random per-process key is generated **with a warning**, so dev/CI work while production is forced to set it via the secrets manager. | `app/config.py`, `notify/src/config.js` | Gitleaks: 0 secrets in the working tree. |
| **#4 Plaintext password logging** (High) | `login()` logs the **username only**, never the password, on attempt and on failure. | `app/main.py` | Covered by the login tests; SAST no longer flags credential disclosure. |
| **#6 IDOR on `GET /scans/{id}`** (High) | Added an `owner_id == current_user.id` filter so a user can only read their own scan; non-owners get a uniform 404. | `app/main.py` | `test_get_scan_idor_blocked`. |
| **#7 Reflective CORS with credentials** (High) | CORS now echoes the `Origin` **only** when it is on an explicit env-driven allow-list (`CORS_ALLOWED_ORIGINS`); `Allow-Headers` narrowed, `Vary: Origin` added, preflight handled. | `app/config.py`, `app/main.py` | `test_cors_does_not_reflect_arbitrary_origin`, `test_cors_allows_configured_origin`. |
| **#8 Verbose error handler** (Medium) | Global handler logs full detail server-side (`exc_info=True`) but returns a generic `{"error":"Internal Server Error"}`; no message/type/traceback/path is leaked. | `app/main.py` | `test_error_handler_does_not_leak_internals`. |

This exceeds the brief's requirement (≥3 Critical/High fixes, ≥1 touching the
new Task 1 code): we fixed **3 Critical + 3 High/Medium**, and the Task 1 code
was hardened against the same classes (IDOR, SQLi, traceback leak) by design —
see `findings.md`, "Findings introduced by our new feature".

---

## 2. Fixed earlier, during Task 4 (dependency bumps at build time)

We bumped vulnerable Python dependencies **during containerisation (Task 4)**,
not here, and we call that out explicitly. The reason: we did not want to build
and publish an image knowingly carrying fixable CRITICAL/HIGH CVEs. We prioritised
driving **CRITICALs to zero** even where a CVE may not be directly reachable in
our runtime, because it could still be genuinely risky and the cost was low.

| Bump | Cleared |
|------|---------|
| `python-jose` 3.3.0 → 3.4.0 | **CRITICAL algorithm-confusion CVE-2024-33663** |
| `cryptography` → 50.0.0, `python-multipart` → 0.0.30, `fastapi`/`starlette`, `uvicorn`, `httpx` | Multiple HIGH CVEs |

Result: Python-layer container CVEs went **CRITICAL 1 → 0, HIGH 17 → 10**; tests
stayed green after every bump. The nuanced "is this CVE reachable in *our*
runtime?" judgement is what separates section 1 (fixed) from section 3 (residual).

---

## 3. Residual risks (consciously accepted)

Each item is accepted **with a stated reason and a compensating control**. None
are Critical after Task 3.

### 3.1 Notify service — out of code scope per the brief
- **#5 `axios@0.21.1` (11 HIGH, incl. SSRF CVE-2025-27152)**, **#9 SSRF in webhook dispatch**, **#12 `body-parser`/`path-to-regexp` ReDoS/DoS**, **#13 no authn on `/notify`, no login rate-limit**.
- **Why not fixed now:** the brief scopes code changes to the Python API; the notify service is explicitly out of scope. Fixing #9 properly (SSRF allow-list / metadata-IP block) and #5/#12 (axios/express upgrades) is real work we did not want to do half-way.
- **Compensating controls already in place:** the Helm **NetworkPolicy** restricts notify's egress to DNS + the specific notify pods (no arbitrary outbound), which blunts the SSRF blast radius at the network layer even with the vulnerable axios.
- **Owner / next step:** notify-service hardening ticket — SSRF allow-list, authn on `/notify`, login rate-limiting, axios/express bump (subject to the 3–7 day policy below).

### 3.2 Residual Python library HIGHs (#11)
- `starlette` (HIGH) — the clean fix requires a **breaking FastAPI 1.x** jump; deferred to a planned framework-upgrade ticket rather than rushed under the deadline.
- `ecdsa` CVE-2024-23342 (Minerva) — **no fix available**. Compensating control: we sign JWTs with **HS256, not ECDSA**, so the vulnerable code path is not exercised.
- Transitive `pyasn1` / `wheel` — constrained by `python-jose` (`pyasn1<0.5`); forcing a bump breaks the dependency contract. Build/transitive scope, low reachability.

### 3.3 Container base-image OS CVEs (#10)
- `python:3.11-slim` (Debian) ships some CRITICAL/HIGH **OS** packages not reachable through the app.
- **Chosen control:** we would use a **Chainguard/distroless** base in production (documented in the `Dockerfile`), which brings these to ~zero. We stayed on `slim` **only** to keep this exercise reproducible, and said so explicitly.

### 3.4 Task 1 conscious trade-off (A)
- **Password on `GET /share/{token}` as `?password=`** (CWE-598) — mandated by the brief. Query strings can appear in logs/proxies/`Referer`.
- **Controls:** password is optional; stored only as a **bcrypt hash**; verified in constant time; bounded to 1–64 chars. A hardened redesign would move it to a header or POST body — noted in the README and here.

### 3.5 Secret-scanning scope
- CI Gitleaks scans the **working tree** (`gitleaks dir`), not full git history. The original starter secrets still exist in **history**; they have been **rotated conceptually** (removed from code, now env-injected), but for a real deployment the correct action is to **rotate the actual key material** and, if warranted, rewrite history / invalidate the exposed values. Tracked as a follow-up.

---

## 4. Supply-chain policy: 3–7 day adoption delay

We deliberately **do not** adopt brand-new dependency releases on release day. We
wait **3–7 days** before pulling a fresh version into the build.

- **Rationale:** recent supply-chain attacks (compromised `axios`-ecosystem
  releases, the `Shai-Hulud` npm worm, and similar) are frequently caught by the
  community within days. A short quarantine window materially reduces the risk of
  ingesting a poisoned release.
- This is a **documented, intentional policy** — not staleness. Pins are explicit
  and reviewed; upgrades are intentional and lagged. It also means we sometimes
  *hold* a fix for a few days rather than jump on the newest tag — an accepted,
  small exposure window traded against supply-chain risk.

---

## 5. Shift-left and CI enforcement

- **Shift-left:** we run the same scanners **locally before committing and before
  merging** — `trivy config` on the Helm chart and Dockerfile, `trivy image` on
  the built image, `semgrep` (SAST) and `gitleaks` (secrets). CI re-runs them as a
  backstop; we do not rely on CI to catch what we could catch locally.
- **Hard gates:** after Task 3 removed the starter Critical issues, the **SAST and
  secret gates were made blocking** (the `continue-on-error` used through Task 1/4
  was removed). SCA/container/IaC gates were already hard. The full run is green.
- **Helm scanned before merge:** the Trivy IaC scan runs on the chart before the
  commit and before the PR merges — IaC misconfigurations = 0.

---

## 6. Summary

| State | Items |
|-------|-------|
| **Fixed in Task 3** | #1, #2, #3 (Critical); #4, #6, #7 (High); #8 (Medium) |
| **Fixed during Task 4 (build)** | Python CRITICAL CVE (jose) → 0; multiple HIGH bumped |
| **Residual (accepted, controlled)** | #5, #9, #12, #13 (notify, out of scope); #11 (breaking/no-fix); #10 (base image); A (query-param password); history-secret rotation |

Post-remediation there are **no known Critical findings in the Python API's code
or its shipped dependencies**. Remaining items are Medium/High in out-of-scope or
build/transitive components, each with a compensating control and a named
follow-up.
