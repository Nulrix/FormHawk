import argparse
import asyncio
import json
import random
import re
import string
import time
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, urlencode, urlunparse, ParseResult

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box


# ---- Helper functions ----

def norm_url(u: str) -> str:
    """Normalize a URL by stripping fragments and default ports."""
    u = urldefrag(u)[0]
    p = urlparse(u)
    netloc = p.netloc
    if (p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443):
        netloc = p.hostname or ""
    return urlunparse(ParseResult(p.scheme, netloc, p.path or "/", p.params, p.query, ""))


def same_origin(a: str, b: str) -> bool:
    """Return True if URLs a and b share the same scheme, host and port."""
    pa, pb = urlparse(a), urlparse(b)
    return (
        pa.scheme == pb.scheme
        and pa.hostname == pb.hostname
        and (pa.port or -1) == (pb.port or -1)
    )


def rand_marker(n: int = 10) -> str:
    """Generate a random marker string prefixed with 'fhk_' for active probes."""
    return "fhk_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def cookie_audit(headers: httpx.Headers) -> dict:
    """
    Perform a simple cookie audit by examining Set-Cookie headers for missing
    HttpOnly, Secure and SameSite attributes.
    """
    issues = []
    sc = headers.get_list("set-cookie")
    for c in sc:
        c_low = c.lower()
        if "httponly" not in c_low:
            issues.append("Cookie missing HttpOnly")
        if "secure" not in c_low:
            issues.append("Cookie missing Secure")
        if "samesite" not in c_low:
            issues.append("Cookie missing SameSite")
    return {"set_cookie_count": len(sc), "issues": sorted(set(issues))}


def header_audit(headers: httpx.Headers) -> dict:
    """
    Check for the presence of important security headers and provide hints if they
    are misconfigured or weak.
    """
    SEC_HEADERS = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "referrer-policy",
        "x-content-type-options",
    ]
    present = {h: (h in {k.lower() for k in headers.keys()}) for h in SEC_HEADERS}
    hints = []
    csp = headers.get("content-security-policy")
    if csp and "'unsafe-inline'" in csp.replace(" ", ""):
        hints.append("CSP allows 'unsafe-inline'")
    xfo = headers.get("x-frame-options")
    if xfo and xfo.lower() not in ("deny", "sameorigin"):
        hints.append(f"X-Frame-Options weak: {xfo}")
    hsts = headers.get("strict-transport-security")
    if hsts and "max-age" not in hsts.lower():
        hints.append("HSTS missing max-age")
    return {"present": present, "hints": hints}


def extract_forms(html: str, base_url: str) -> list:
    """
    Parse HTML for form tags, returning a list of dictionaries with method,
    resolved action URL, input names/types, and whether a potential CSRF token
    input is present.
    """
    out = []
    soup = BeautifulSoup(html, "html.parser")
    for f in soup.find_all("form"):
        method = (f.get("method") or "GET").upper()
        action = f.get("action") or ""
        action_full = norm_url(urljoin(base_url, action)) if action else base_url
        inputs = []
        for inp in f.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            typ = inp.get("type") or inp.name
            if name:
                inputs.append({"name": name, "type": typ})
        has_csrf = any(re.search(r"csrf|token|authenticity", i["name"], re.I) for i in inputs)
        out.append({
            "method": method,
            "action": action_full,
            "inputs": inputs,
            "csrf_token_present": bool(has_csrf),
        })
    return out


def extract_links_and_params(html: str, base_url: str, origin: str) -> tuple[list, list]:
    """
    Extract same-origin hyperlinks and query parameter names (with counts) from the page.
    Returns a tuple of (links, params_list).
    """
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    params = {}
    for a in soup.find_all("a", href=True):
        href = norm_url(urljoin(base_url, a["href"]))
        if same_origin(origin, href):
            urls.add(href)
            pq = urlparse(href).query
            for k, _ in parse_qsl(pq, keep_blank_values=True):
                params.setdefault(k, 0)
                params[k] += 1
    return list(urls), [
        {"name": k, "count": v}
        for k, v in sorted(params.items(), key=lambda x: -x[1])
    ]
