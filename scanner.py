import ipaddress
import os
import socket
from urllib.parse import urlparse
import httpx
from .schemas import Finding

def _resolve_all(host):
    try:
        return {ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(host, None)}
    except (OSError, ValueError):
        return set()

def validate_scope(url):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only valid HTTP(S) URLs are supported.")
    host = parsed.hostname.lower()
    if host in {"localhost"}:
        return
    ips = _resolve_all(host)
    if not ips:
        raise ValueError("Target could not be resolved.")
    if all(ip.is_loopback or ip.is_private for ip in ips):
        return
    allow = {x.strip().lower() for x in os.getenv("ASSESSMENT_ALLOWLIST", "").split(",") if x.strip()}
    if host not in allow or os.getenv("ALLOW_PUBLIC_TARGETS", "false").lower() != "true":
        raise ValueError("Target is outside the configured assessment scope.")

def header_findings(headers):
    h = {k.lower(): v for k, v in headers.items()}
    checks = [
        ("content-security-policy", "Missing Content-Security-Policy", "MEDIUM",
         "Define a restrictive Content Security Policy; validate it in report-only mode first."),
        ("strict-transport-security", "Missing Strict-Transport-Security", "MEDIUM",
         "Enable HSTS after confirming the application is consistently served over HTTPS."),
        ("x-content-type-options", "Missing X-Content-Type-Options", "LOW",
         "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Missing Referrer-Policy", "LOW",
         "Set a privacy-conscious Referrer-Policy."),
        ("permissions-policy", "Missing Permissions-Policy", "LOW",
         "Disable browser features that the application does not require.")
    ]
    out = []
    for key, title, severity, fix in checks:
        if key not in h:
            out.append(Finding(id=f"WEB-{key.upper()}", title=title, severity=severity,
                               evidence=f"Response did not include {key}.", recommendation=fix))
    if "x-frame-options" not in h and "content-security-policy" not in h:
        out.append(Finding(id="WEB-FRAME", title="No clickjacking defense detected",
            severity="MEDIUM", evidence="Neither X-Frame-Options nor CSP was present.",
            recommendation="Configure CSP frame-ancestors and consider X-Frame-Options for legacy clients."))
    return out

def cookie_findings(headers):
    out = []
    cookies = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
    for n, cookie in enumerate(cookies, 1):
        lower = cookie.lower()
        for attr, severity in [("secure", "MEDIUM"), ("httponly", "MEDIUM"), ("samesite", "LOW")]:
            if attr not in lower:
                out.append(Finding(id=f"COOKIE-{n}-{attr}", title=f"Cookie missing {attr}",
                    severity=severity, evidence=f"Set-Cookie item {n} did not include {attr}.",
                    recommendation=f"Set the {attr} cookie attribute where appropriate."))
    return out

async def assess(url, timeout=8):
    validate_scope(url)
    async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=False,
        headers={"User-Agent": "WebSecurityPostureAPI/1.0"}) as client:
        response = await client.get(url)
    findings = header_findings(response.headers) + cookie_findings(response.headers)
    counts = {s: sum(f.severity == s for f in findings) for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
    return {"target": url, "status_code": response.status_code,
            "final_url": str(response.url), "findings": [f.model_dump() for f in findings],
            "counts": counts}
