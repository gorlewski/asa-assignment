# Security Automation Engineer — Take-Home Assignment

Welcome. This assignment is designed to reflect the real work of a Lead Security Automation Engineer: extending an existing service, identifying and assessing security risks, remediating them with code, and deploying it securely. There are no trick questions — we are evaluating your depth of knowledge, your judgment under constraints, and your ability to communicate risk.

**Estimated time: 4–6 hours.** We respect your time. If you find yourself going significantly over, scope down rather than rushing.

---

## Background

**VulnTracker** is a two-service system for managing vulnerability scan results:

- **`app/`** — Python/FastAPI REST API. Security teams use it to log findings, track remediation, and share reports with stakeholders.
- **`notify/`** — Node.js/Express notification service. Intended to dispatch webhook events to registered endpoints when scan records are created or updated.

Both services are working but imperfect internal prototypes. Neither has gone through a formal security review. The Python API calls the notification service in the background whenever a scan is created or updated — start both services to see the full flow.

---

## Getting Started

**Create your own repository for this assignment.** Do not fork — your solution must be in a fresh repo. You may use the starter code as a base, but your work must be in your own repo.

```bash
# 1. Clone the assignment repo locally
git clone https://github.com/cloudtriquetra/asa-assignment.git
cd asa-assignment

# 2. Point it at your own new GitHub repo (create one first at github.com)
git remote set-url origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

From here, work on your own repo and share its URL when you submit.

**Requirements:** Python 3.11 (exactly — see CI), Node.js 20+, Docker

**Python API (`app/`)**

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The API must be started from inside the `app/` directory — the modules use bare imports and won't resolve from the repo root:

```bash
cd app
uvicorn main:app --reload
```

Available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

Run the Python test suite from the **repo root**:

```bash
pytest tests/ -v
```

**Notification Service (`notify/`)**

```bash
cd notify
npm install
npm start
```

Available at `http://localhost:3001`.

Run the Node.js test suite (stop the notify service first if it is running — the test suite starts its own server on the same port):

```bash
cd notify
npm test
```

---

## Feature: Shared Report Link (Task 1)

Share a specific scan result with an external stakeholder via a unique,
time-limited link with optional password protection.

| Method | Path                     | Auth         | Description                                                                                   |
| ------ | ------------------------ | ------------ | --------------------------------------------------------------------------------------------- |
| `POST` | `/scans/{scan_id}/share` | Bearer token | Generate a share token for a scan you own. Optional `password` in the body. Returns `share_url`. |
| `GET`  | `/share/{token}`         | None (public) | Return the scan if the token is valid and unexpired. If protected, requires `?password=`.     |

Example:

```bash
# Generate a link (optionally password-protected)
curl -X POST http://localhost:8000/scans/1/share \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "optional-secret"}'
# -> {"share_url": "http://localhost:8000/share/<token>", "expires_at": "..."}

# Access the shared scan
curl "http://localhost:8000/share/<token>?password=optional-secret"
```

### Design and security decisions

- **Token**: 256-bit CSPRNG value via `secrets.token_urlsafe(32)` — unguessable and non-sequential.
- **Token storage**: only the SHA-256 digest of the token is persisted (`share_links.token_hash`); the raw token is never stored, so a database disclosure does not yield usable links.
- **Password**: optional; hashed with bcrypt via the existing `passlib` context and verified in constant time. Plaintext is never stored or logged.
- **Expiry**: enforced server-side; links live for 24h (`SHARE_LINK_TTL_HOURS`, overridable via env).
- **Access control**: only the scan owner can create a share link; requests for another user's scan return `404` (no existence oracle).
- **Data minimisation**: the public projection omits `owner_id` and `remediation_notes` so a public link does not leak internal ownership or remediation detail.
- **Uniform errors**: unknown, expired and invalid tokens all return a generic `404`; bad/missing passwords return `401` — no leakage of which case occurred.
- **`share_url` construction**: built from the incoming request host (`request.base_url`) with a fallback to `APP_BASE_URL` (default `http://localhost:8000`). Note: the `Host` header is client-controlled and can be spoofed; acceptable for this prototype and called out here.

## Your Tasks

### Task 1 — Extend the App _(~1–1.5 hrs)_

Implement the **"Shared Report Link"** feature:

> As a VulnTracker user, I want to share a specific scan result with an external stakeholder (e.g. a customer or auditor) via a unique link. The link must expire after **24 hours** and must support **optional password protection**.

Add the following endpoints to the app:

| Method | Path                     | Auth          | Description                                                                                                              |
| ------ | ------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `POST` | `/scans/{scan_id}/share` | Bearer token  | Generate a share token for a scan. Accepts optional `password` in the request body. Returns `{ "share_url": "..." }`     |
| `GET`  | `/share/{token}`         | None (public) | Return the scan data if the token is valid and not expired. If password-protected, require a `password` query parameter. |

Implementation choices are yours. We will read and evaluate the code you write here — including the security properties of your implementation. For the `share_url` value, use the incoming request's host, or hard-code `http://localhost:8000` for the prototype — document whichever you choose.

---

### Task 2 — Security Analysis _(~1.5 hrs)_

#### 2a. Run the required scans

You must run **all four** of the following scan categories. Select an appropriate open-source or free-tier tool for each — your tool choices are part of the evaluation.

| Scan type                                      | What it covers                                                                         |
| ---------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Static Application Security Testing (SAST)** | Source code — identify insecure coding patterns, injection risks, hardcoded secrets    |
| **Dependency / SCA vulnerability scan**        | Third-party packages — known CVEs in pinned dependencies                               |
| **Container image scan**                       | The Docker image you build — OS packages, installed libraries, misconfigurations       |
| **Infrastructure-as-Code (IaC) security scan** | Your Helm chart or Terraform — misconfigurations, insecure defaults, policy violations. Complete Task 4 first, then run this scan. |

Save the raw JSON output of each tool to the `reports/` directory, named clearly by scan type:

```
reports/
├── sast.<tool>.json
├── sca.<tool>.json
├── container.<tool>.json
└── iac.<tool>.json
```

#### 2b. Prioritised findings

Write a `docs/findings.md` with a table of security findings, sourced from your scans and your own manual review. For each finding:

- Tool and scan type that detected it (or "manual")
- Severity (your assessment — justify it)
- Business impact in the context of _this specific application_
- Whether it is in the starter code or in your new feature

**Do not copy-paste tool output.** We are evaluating your ability to interpret findings and apply business context to prioritisation — not your ability to run a command.

---

### Task 3 — Remediate _(~1 hr)_

- Fix **at least 3 critical or high severity findings** in code. Show the changes clearly (they will be visible in your git diff / PR).
- At least one fix must be in the code you wrote in Task 1.
- For findings you do not fix, document why in `docs/remediation-plan.md`: what is the residual risk, what effort would remediation require, and what compensating controls (if any) exist?

---

### Task 4 — Containerisation and Deployment Artifacts _(~30–45 min)_

#### Dockerfile (mandatory)

Write a production-grade `Dockerfile` for the **Python FastAPI service** (`app/`). It must:

- Use a minimal, pinned base image
- Run as a non-root user
- Include a `HEALTHCHECK`
- Not embed secrets or credentials

The container image must build successfully and the app must be reachable via `docker run`. Include build and run instructions in your README.

#### Infrastructure

Add either a `terraform/` or `helm/` directory (your choice) that could deploy this service to a Kubernetes cluster or cloud environment. Your deployment must:

- Source secrets from a secrets manager (not hardcoded in manifests or env vars)
- Restrict network ingress to only what is required
- Define resource limits and security contexts

---

### Task 5 — Executive Summary _(~30 min)_

Write `docs/executive-summary.md` as if you are presenting to a CISO who has 5 minutes.

Cover:

1. The overall security posture of the application before and after your work
2. The top 3 residual risks and the reason they were not fully remediated
3. Your recommended next steps if this were a real production service

No jargon. No tool names in the first paragraph. Your audience cares about business risk, not CVE numbers.

---

## Submission

Push your completed solution to your own GitHub repository and share the URL with us. Your repository must contain:

```
/
├── app/                        # extended Python API code
├── notify/                     # Node.js notification service (no changes required)
├── Dockerfile                  # mandatory (may cover one or both services)
├── reports/
│   ├── sast.<tool>.json
│   ├── sca.<tool>.json
│   ├── container.<tool>.json
│   └── iac.<tool>.json
├── terraform/  OR  helm/
├── docs/
│   ├── findings.md
│   ├── remediation-plan.md
│   └── executive-summary.md
├── tests/                      # updated if you added Python tests
└── README.md                   # update with Docker build/run instructions
```

CI must pass (green) on your repo before submission.

---

## What We Are Looking For

We are not grading on volume. We are grading on judgment.

- **Security depth**: Did you find the real issues? Did you prioritise them correctly for this application?
- **Implementation security**: Does your new feature introduce, or avoid, new vulnerabilities?
- **Remediation quality**: Are your fixes correct and complete? Are your deferral reasons honest?
- **Deployment security**: Does your container and infrastructure configuration reflect real-world security practices?
- **Communication**: Would a non-technical executive understand your summary?

Good luck. If anything in the brief is ambiguous, document your assumption and proceed.
