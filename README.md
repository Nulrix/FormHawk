# FormHawk — Form & Endpoint Mapper with Passive Security Checks

FormHawk crawls a target site (within the same origin), maps forms and parameters, audits cookies and security headers, and (optionally) performs a safe reflection check with a unique marker. **Default behaviour is passive**, meaning only GET requests are sent and no data is modified.

> **LEGAL & ETHICAL NOTICE**: Use this tool only on systems you own or have explicit permission to test. FormHawk performs harmless GET requests by default. Active checks are limited to adding a benign marker via the query string and must be explicitly enabled.

## Quick start

Install dependencies using a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# run a passive crawl with depth 2 and save a JSON report
python3 formhawk.py -u https://target.example -d 2 -o report.json

# enable the safe active reflection probe on GET endpoints. By default probes all endpoints
python3 formhawk.py -u https://target.example --active
```

## Features

- **Async crawling** within the same origin (configurable depth and URL limits).
- **Form extraction** (method, action, input names/types) with basic CSRF token detection.
- **Parameter inventory** from discovered links (counts occurrences of each parameter name).
- **Cookie audit**: checks `HttpOnly`, `Secure`, and `SameSite` flags on `Set-Cookie` headers.
- **Security header audit**: checks for the presence of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `Referrer-Policy` and `X-Content-Type-Options` headers and provides high‑level hints if misconfigured.
- **Optional active reflection probe**: appends a unique inert marker to query strings on GET endpoints and reports whether the marker appears in the response body. This can highlight pages vulnerable to reflected XSS or SSRF without performing any malicious payloads. No limit is enforced on the number of probes unless specified.
- **JSON export** of the full report plus a human‑friendly summary in the terminal.

## Ethics & Safety

- **Passive by default**: FormHawk will never send POST requests or modify server state unless extended by you. The active probe uses only GET requests and requires the `--active` flag.
- **Rate limiting (optional)**: By default there is no rate limiting. You can throttle requests per second with the `--rps` option to avoid overwhelming the target server.
- **Scope control**: The crawler only follows links within the same origin as the base URL to prevent out‑of‑scope requests.
- Always obtain **explicit authorization** before scanning any system. Unauthorized scanning is illegal.

## Files

- `formhawk.py`: The main CLI tool implementing the crawler, form extractor, parameter mapper, cookie/header audit, and optional active reflection probe.
- `requirements.txt`: Lists Python dependencies (`httpx`, `beautifulsoup4`, `rich`).

## Extending

- Add additional security checks (e.g. password autocomplete detection, mixed content checks) by modifying `formhawk.py`.
- Integrate with other tools by importing `formhawk.py` as a module and using its functions.
- Build a small web UI or API around the JSON output for team‑wide reports.

MIT licensed. Created by **Nulrix** for educational and authorized penetration testing use.
