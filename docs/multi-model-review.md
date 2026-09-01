# Multi-Model Security Review (Gemini second opinion)

As promised in the summaries, we ran a **second-opinion review with a different
model family**. The main work was done with **Claude Opus 4.8** (Anthropic); the
review was done with **Gemini** (Google). Using a different family is deliberate:
the same family tends to repeat the same blind spots, so an independent reviewer
is more likely to catch what the first model missed.

This page records what the review found and, importantly, **which items we then
fixed in code (with tests) versus which we keep as recommendations**.

> Process note: the reviewer initially reported creating a branch that did not
> actually exist in the repo — a good reminder that LLM output must be verified,
> not trusted. We located the real changes, checked every claim against the code,
> hardened the genuine fixes, added regression tests, and dropped the rest to
> documented recommendations. That verification loop is the whole point of a
> multi-model review.

## Fixed in code (with regression tests)

### 1. CRITICAL — Broken tenant isolation (BOLA/IDOR) in `GET /scans/search`
When we fixed the SQL injection in `search_scans_by_query` (Task 3), we
parameterised the query but **did not add an `owner_id` filter**. The other scan
routes (`GET /scans`, `GET /scans/{id}`) do filter by owner, so search was an
inconsistency: any authenticated user could search and read **other tenants'**
scans. This is the most important finding of the review.
**Fix:** `search_scans_by_query` now takes `owner_id` and constrains the query to
the caller's own scans; `search_scans` passes `current_user.id`.
**Test:** `test_search_is_tenant_isolated` — another user searching for a unique
marker gets 0 results; the owner gets 1.

### 2. HIGH — Host header injection in the share URL
The share link was built from `request.base_url`, which derives from the
client-controlled `Host` header. An attacker could spoof it to mint links
pointing at a malicious domain (phishing / password capture).
**Fix:** the URL is now built from the trusted `APP_BASE_URL` configuration only.
**Test:** `test_share_url_ignores_spoofed_host_header` — a spoofed `Host` does not
appear in the generated `share_url`.

### 3. MEDIUM — Unbounded pagination on `GET /scans` (DoS)
`limit` defaulted to 50 but had no maximum, so `limit=1000000000` could exhaust
memory / overload the database.
**Fix:** `limit` is now `Query(50, ge=1, le=100)` and `skip` is `Query(0, ge=0)`.
**Test:** `test_scans_limit_is_bounded` — an oversized limit returns 422.

### 4. LOW/MEDIUM — Explicit bcrypt work factor
Passlib was initialised with defaults. We now pin `bcrypt__rounds=12` explicitly
so the KDF cost is consistent and strong across environments.

## Recommendations kept as notes (not code changes)

### 5. SUPPLY CHAIN — Hash-pinned dependencies
Versions are pinned (`==`) but not **hash**-pinned, so a tampered PyPI package
under the same version could slip through. Recommended for production: a lockfile
with hashes plus `pip install --require-hashes` (e.g. `poetry.lock`). Captured as
a note in the `Dockerfile`; not applied here to keep the exercise reproducible.

### 6. DESIGN — Password via query string on `GET /share/{token}` (CWE-598)
Already a known, documented trade-off (the brief mandates `?password=`). The
review agreed it should be flagged; in a real system we would push back and move
the password to a header or a POST body. Comment clarified at the route.

## Outcome

The review found a **genuine critical issue** (tenant isolation in search) that
the first pass missed, plus a high and a medium. All three are now fixed with
tests; the remaining two are documented recommendations. This is exactly the
value multi-model validation is meant to add: an independent pass caught a real
authorization gap that a same-family re-read would likely have missed.
