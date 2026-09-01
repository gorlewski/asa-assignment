# Executive Summary — VulnTracker Security Work

**Audience:** CISO / security leadership
**Reading time:** ~4–5 minutes

## What this is

VulnTracker is a service that stores vulnerability scan results and lets teams
share them with external stakeholders through a public link. Because it holds
data about where an organisation is weak, and because it exposes a public,
unauthenticated endpoint, its security matters more than an average internal app.

We extended the service with a new feature, ran a full security analysis, fixed
the most important problems, and packaged it for a secure deployment.

## Security posture: before vs after

**Before (starter code).** The application had several serious problems that
would each be enough to compromise it:

- **Authentication could be bypassed completely.** The token check accepted the
  "none" algorithm, so anyone could forge a token for any user.
- **The database could be read through SQL injection** on the search endpoint.
- **Secrets were hardcoded in the source** (JWT signing key, DB password, API
  keys) — and the repository is public, so anyone could read them.
- **Passwords were written to the logs**, users could read other users' data by
  changing an ID in the URL (IDOR), any website could call the API with the
  user's credentials (open CORS), and error responses leaked stack traces.

**After (our work).** Every one of the problems above in the Python API is
fixed, with an automated test for each fix so it cannot come back silently:

- The "none" algorithm is rejected; only the real signing algorithm is accepted.
- The search query is parameterised; SQL injection is closed.
- All secrets now come from the environment (a secrets manager in production);
  nothing sensitive is in the code.
- Passwords are no longer logged, cross-tenant access is blocked, CORS is
  limited to an approved list, and errors return a generic message while full
  detail is logged only on the server.

We also **hardened the deployment**: a production-grade container that runs as a
non-root user with a read-only filesystem, and a Helm chart that pulls secrets
from a secrets manager, restricts network traffic, sets resource limits and
applies strict security settings. Security scanners (Semgrep, Trivy, Gitleaks)
run on every change in CI and **block the merge** if they find a critical issue.

**Net result:** there are **no known critical findings left in the API code or
in the dependencies we ship**. The remaining items are lower severity and sit in
out-of-scope or third-party components, each with a control in place.

## Top 3 residual risks

1. **The notification service is not hardened (out of scope for this exercise).**
   It can be pointed at internal addresses (SSRF) and uses an old HTTP library
   with known issues. *Control today:* the network policy stops it from reaching
   arbitrary destinations. *Next:* an allow-list, authentication and a library
   upgrade.
2. **Some third-party library issues have no clean fix yet.** A couple require a
   breaking framework upgrade, and one cryptography library has no patch. *Control
   today:* we do not use the vulnerable code path (we sign with HS256, not the
   affected algorithm). *Next:* schedule the framework upgrade.
3. **Old secrets still exist in the git history.** We removed them from the code,
   but a real deployment must **rotate the actual key material**, because the old
   values were once public. *Next:* rotate and invalidate the exposed secrets.

## Recommended next steps

- **Rotate all previously exposed secrets** and confirm production reads them
  from the secrets manager.
- **Harden the notification service** (SSRF allow-list, authentication, library
  upgrade, login rate-limiting).
- **Move to a minimal, hardened base image** (Chainguard or Google Distroless)
  in production; this removes most operating-system vulnerabilities and a lot of
  base-image hardening work in one step. We stayed on the standard "slim" image
  only to keep this exercise easy to reproduce.
- **Keep the 3–7 day delay policy** before adopting brand-new dependency
  versions, to reduce exposure to supply-chain attacks (recent incidents in the
  npm ecosystem show why this matters).

## How the work was done (quality note)

The work was done with Cursor (private Pro subscription) using **Claude Opus 4.8**
as the main model. To reduce single-model blind spots, we plan a **second-opinion
review with Gemini** — a different model family, so it reviews the findings
independently rather than repeating the same assumptions. Full technical detail,
decisions and trade-offs are in [`technical-summary.md`](./technical-summary.md)
and [`remediation-plan.md`](./remediation-plan.md).
