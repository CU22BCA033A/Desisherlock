"""Web header analysis + a short, explicitly curated misconfig-path check.

This is a recon/misconfig check, not a directory-buster: the path list
below is intentionally short and well-known. Point --wordlist-style
brute-forcing tools at a target yourself if you want to go further than
this.
"""
import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Short, curated list of well-known misconfiguration indicators.
MISCONFIG_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/robots.txt",
    "/server-status",
    "/.well-known/security.txt",
    "/.htaccess",
    "/wp-config.php.bak",
    "/backup.zip",
    "/.svn/entries",
    "/config.php.bak",
    "/.DS_Store",
    "/phpinfo.php",
]


def _normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def check_headers(url, timeout=10):
    url = _normalize_url(url)
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {"url": url, "error": f"Could not fetch URL: {e}"}

    present = {}
    missing = []
    for header in SECURITY_HEADERS:
        value = response.headers.get(header)
        if value is not None:
            present[header] = value
        else:
            missing.append(header)

    return {
        "url": url,
        "status_code": response.status_code,
        "headers_present": present,
        "headers_missing": missing,
        "server": response.headers.get("Server"),
    }


def check_misconfig_paths(url, timeout=10):
    url = _normalize_url(url)
    findings = []
    for path in MISCONFIG_PATHS:
        try:
            response = requests.get(url + path, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        if response.status_code < 400:
            findings.append({
                "path": path,
                "status_code": response.status_code,
                "content_length": len(response.content),
            })
    return findings


def recon(url, timeout=10):
    """-web: header analysis + common exposed-path check."""
    header_result = check_headers(url, timeout=timeout)
    if "error" in header_result:
        return header_result
    header_result["exposed_paths"] = check_misconfig_paths(url, timeout=timeout)
    return header_result
