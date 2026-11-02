# C1 — Web Security Posture API

Defensive HTTP configuration assessment for explicitly scoped web applications.

## Features
- Scope allowlist (hostnames/IPs) with public-target access disabled by default.
- HTTP response and redirect metadata.
- Security header checks: CSP, HSTS, frame protection, MIME sniffing, referrer and permissions policy.
- Cookie attribute checks: Secure, HttpOnly, SameSite.
- Structured findings with severity, evidence and remediation.
- FastAPI endpoints and JSON response model.

## Run
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open `/docs`. Add an authorized hostname to `ASSESSMENT_ALLOWLIST` as comma-separated values. Localhost and loopback are allowed for development. Set `ALLOW_PUBLIC_TARGETS=true` only when you have explicit authorization.

```bash
curl -X POST http://127.0.0.1:8000/assess -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:8000"}'
```

## Tests
```bash
pytest -q
```

## Limitations
This is a posture review helper, not a full DAST product or penetration test. It does not crawl, authenticate, exploit, or verify business-logic vulnerabilities.
