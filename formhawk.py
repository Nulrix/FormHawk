#!/usr/bin/env python3    
"""
FormHawk — Form & Endpoint Mapper with Passive Security Checks (MVP)

This tool performs passive crawling and auditing of a target website to discover forms,
URL parameters, cookie settings, and security headers. It can optionally perform a safe
reflection probe on GET endpoints by appending a benign marker to the query string and
reporting whether the marker appears in the response body. The default behaviour is
fully passive and sends only GET requests.

Ethical use only: you must own or have explicit permission to scan the target.

Created by Nulrix.

Usage examples:
    # passive crawl with depth 2, limit 200 pages, save report to file
    python3 formhawk.py -u https://example.com -d 2 -m 200 -o report.json

    # enable active reflection probe on up to 50 endpoints
    python3 formhawk.py -u https://example.com --active --max-active 50

"""
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

# Create a global console for printing across functions
console = Console()


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


async def fetch(client: httpx.AsyncClient, url: str) -> tuple[httpx.Response | None, str | None]:
    """Make an HTTP GET request and return (response, error)."""
    try:
        r = await client.get(url, timeout=8.0, follow_redirects=False)
        return r, None
    except Exception as e:
        return None, str(e)


async def crawl(base_url: str, max_depth: int, max_urls: int, concurrency: int, rps: float) -> dict:
    """
    Crawl the target starting from base_url up to max_depth and max_urls.
    Returns a dictionary containing all visited pages with extracted forms, params,
    cookie audits and header audits. Only same-origin links are followed.
    """
    origin = norm_url(base_url)
    seen, queue = set([origin]), asyncio.Queue()
    await queue.put((origin, 0))
    results = {}
    # rate limiting variables
    bucket_tokens = rps
    last_time = time.monotonic()

    async with httpx.AsyncClient(
        headers={"User-Agent": "FormHawk/0.1 (edu only)"},
        limits=httpx.Limits(max_connections=concurrency),
        transport=httpx.AsyncHTTPTransport(retries=1),
    ) as client:
        sem = asyncio.Semaphore(concurrency)

        async def rate_gate():
            nonlocal bucket_tokens, last_time
            if rps <= 0:
                return
            now = time.monotonic()
            delta = now - last_time
            last_time = now
            bucket_tokens = min(rps, bucket_tokens + delta * rps)
            need = 1.0
            if bucket_tokens >= need:
                bucket_tokens -= need
                return
            wait = (need - bucket_tokens) / rps
            await asyncio.sleep(wait)
            bucket_tokens = 0.0

        async def worker():
            nonlocal results
            while not queue.empty():
                url, depth = await queue.get()
                # stop if depth limit exceeded or max_urls reached (unless max_urls==0 for unlimited)
                if depth > max_depth or (max_urls > 0 and len(results) >= max_urls):
                    queue.task_done()
                    continue
                await rate_gate()
                async with sem:
                    resp, err = await fetch(client, url)
                page = {
                    "url": url,
                    "status": resp.status_code if resp else None,
                    "headers": dict(resp.headers) if resp else {},
                    "error": err,
                }
                if resp and resp.status_code and 200 <= resp.status_code < 400 and (
                    resp.headers.get("content-type", "").startswith("text/html")
                    or resp.headers.get("content-type", "").startswith("application/xhtml")
                ):
                    html = resp.text
                    page["forms"] = extract_forms(html, url)
                    links, params = extract_links_and_params(html, url, origin)
                    page["params"] = params
                    for l in links:
                        if l not in seen and same_origin(origin, l):
                            # if max_urls is 0, allow unlimited. Otherwise, ensure we won't exceed limit.
                            if max_urls == 0 or len(results) + queue.qsize() < max_urls:
                                seen.add(l)
                                await queue.put((l, depth + 1))
                page["cookie_audit"] = cookie_audit(resp.headers) if resp else {"set_cookie_count": 0, "issues": ["no-response"]}
                page["header_audit"] = header_audit(resp.headers) if resp else {"present": {}, "hints": ["no-response"]}
                results[url] = page
                queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
        await queue.join()
        for w in workers:
            w.cancel()
    return {"base": origin, "pages": results}


async def active_reflection_probe(base_url: str, pages: dict, max_tests: int, concurrency: int, rps: float) -> list[dict]:
    """
    Perform a safe reflection probe on up to max_tests GET endpoints. A unique
    marker is appended as a query parameter and the response body is checked for
    the marker. This can highlight reflected data without injecting actual
    attack payloads.
    """
    candidates = []
    for url, info in pages.items():
        status = info.get("status") or 0
        if 200 <= status < 400:
            candidates.append(url)
    # limit to max_tests if specified (>0); otherwise use all candidates
    if max_tests > 0:
        candidates = candidates[:max_tests]
    marker = rand_marker()
    console.print(f"[yellow]Active reflection marker:[/yellow] {marker}")
    results = []
    bucket_tokens, last_time = rps, time.monotonic()
    async with httpx.AsyncClient(
        headers={"User-Agent": "FormHawk/0.1 (active-probe)"},
        limits=httpx.Limits(max_connections=concurrency),
        transport=httpx.AsyncHTTPTransport(retries=1),
    ) as client:
        sem = asyncio.Semaphore(concurrency)

        def with_marker(u: str) -> str:
            p = urlparse(u)
            q = dict(parse_qsl(p.query, keep_blank_values=True))
            q["_fhk"] = marker
            new_q = urlencode(q, doseq=True)
            return urlunparse(ParseResult(p.scheme, p.netloc, p.path, p.params, new_q, ""))

        async def rate_gate():
            nonlocal bucket_tokens, last_time
            if rps <= 0:
                return
            now = time.monotonic()
            delta = now - last_time
            last_time = now
            bucket_tokens = min(rps, bucket_tokens + delta * rps)
            need = 1.0
            if bucket_tokens >= need:
                bucket_tokens -= need
                return
            wait = (need - bucket_tokens) / rps
            await asyncio.sleep(wait)
            bucket_tokens = 0.0

        async def test(u: str):
            safe = with_marker(u)
            await rate_gate()
            async with sem:
                try:
                    r = await client.get(safe, timeout=8.0, follow_redirects=False)
                    reflected = False
                    if r.headers.get("content-type", "").startswith("text/"):
                        # limit reading to 200k characters
                        body = r.text[:200000]
                        reflected = marker in body
                    results.append({"url": u, "status": r.status_code, "reflected": reflected})
                except Exception as e:
                    results.append({"url": u, "error": str(e)})

        await asyncio.gather(*[test(u) for u in candidates])
    return results


def summarize(report: dict, reflections: list[dict] | None) -> None:
    """Print a summary table of the report and optionally reflection probe results."""
    local_console = Console()
    t = Table(title="FormHawk Summary", box=box.SIMPLE_HEAVY)
    t.add_column("URL", overflow="fold")
    t.add_column("Status")
    t.add_column("Forms")
    t.add_column("Params")
    t.add_column("Cookie Issues")
    t.add_column("Header Hints")
    pages = report["pages"]
    # Show up to 30 results in the summary
    for url, p in list(pages.items())[:30]:
        forms = len(p.get("forms", [])) if p.get("forms") else 0
        params = len(p.get("params", [])) if p.get("params") else 0
        cookie_issues = ", ".join(p.get("cookie_audit", {}).get("issues", [])[:2])
        header_hints = ", ".join(p.get("header_audit", {}).get("hints", [])[:2])
        t.add_row(url, str(p.get("status")), str(forms), str(params), cookie_issues, header_hints)
    local_console.print(t)
    if reflections is not None:
        rtab = Table(title="Active Reflection Probe (GET-only)", box=box.SIMPLE_HEAVY)
        rtab.add_column("URL", overflow="fold")
        rtab.add_column("Status")
        rtab.add_column("Reflected?")
        for r in reflections[:50]:
            rtab.add_row(r.get("url", ""), str(r.get("status", "-")), "YES" if r.get("reflected") else "no")
        local_console.print(rtab)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "FormHawk — Form & Endpoint Mapper (safe by default). "
            "By default there is no limit on pages crawled or active reflection probes and "
            "no rate limit, but you can specify limits via command line flags."
        )
    )
    p.add_argument("-u", "--url", required=True, help="Base URL (include scheme)")
    p.add_argument(
        "-d",
        "--depth",
        type=int,
        default=2,
        help="Max crawl depth (default 2)",
    )
    p.add_argument(
        "-m",
        "--max-urls",
        type=int,
        default=0,
        help=(
            "Max pages to crawl (0 for unlimited). "
            "If 0, the crawler will continue until all reachable pages within depth are visited."
        ),
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=16,
        help="Concurrent requests (default 16)",
    )
    p.add_argument(
        "--rps",
        type=float,
        default=0.0,
        help=(
            "Requests per second budget (0 for unlimited). "
            "If 0, there is no rate limiting."
        ),
    )
    p.add_argument("-o", "--out", help="Write JSON report to file")
    p.add_argument(
        "--active",
        action="store_true",
        help="Enable GET-only reflection probe (adds benign marker)",
    )
    p.add_argument(
        "--max-active",
        type=int,
        default=0,
        help=(
            "Max endpoints to probe when --active (0 for unlimited). "
            "If 0, all eligible endpoints will be probed."
        ),
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    base = norm_url(args.url)
    parsed = urlparse(base)
    if not parsed.scheme or not parsed.netloc:
        console.print(
            "[red]Error:[/red] URL must include scheme and host, e.g. https://example.com",
            style="bold",
        )
        return

    console.print(
        Panel(
            f"[bold]FormHawk[/bold] — passive crawl of [cyan]{base}[/cyan]\n[dim]Use only with permission[/dim]"
        )
    )

    report = asyncio.run(
        crawl(base, args.depth, args.max_urls, args.concurrency, args.rps)
    )

    reflections = None
    if args.active:
        console.print(
            Panel(
                "[yellow]Active reflection probe enabled (GET-only, benign marker)[/yellow]"
            )
        )
        reflections = asyncio.run(
            active_reflection_probe(
                base, report["pages"], args.max_active, args.concurrency, args.rps
            )
        )
        report["active_reflection"] = reflections

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        console.print(Panel(f"Saved JSON report to [green]{args.out}[/green]"))

    summarize(report, reflections)
    console.print(
        Panel(
            "[bold red]ETHICAL NOTICE: Only test targets you own or have permission to test[/bold red]"
        )
    )


if __name__ == "__main__":
    main()
