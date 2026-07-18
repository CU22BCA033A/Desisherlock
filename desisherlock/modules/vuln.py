"""CVE/CVSS lookup against the NVD REST API v2.0.

Never lets a network failure raise up to the CLI - always returns a dict,
using an "error" key to signal failure so the rest of the tool can degrade
gracefully.
"""
import re
import time

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_last_request_time = 0.0


def _throttle(has_api_key):
    """Client-side rate-limit courtesy delay.

    NVD's published limits: 5 requests/30s with no API key, 50/30s with a
    free key. We sleep a conservative amount between calls rather than
    trying to burst up to the limit.
    """
    global _last_request_time
    delay = 2.0 if has_api_key else 6.0
    elapsed = time.time() - _last_request_time
    if elapsed < delay:
        time.sleep(delay - elapsed)


def _extract_cvss(metrics):
    """Extract (score, severity, version) preferring v3.1, then v3.0, v2.

    CVSS data lives at metrics.cvssMetricVXX[0].cvssData.baseScore - not
    in a deprecated top-level 'impact' object.
    """
    if not metrics:
        return None, None, None

    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if score is not None:
                return score, severity, version

    entries = metrics.get("cvssMetricV2")
    if entries:
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = entries[0].get("baseSeverity")
        if score is not None:
            return score, severity, "2.0"

    return None, None, None


def _pick_description(descriptions):
    if not descriptions:
        return None
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return descriptions[0].get("value")


def _parse_cve_item(item):
    cve = item.get("cve", {})
    score, severity, cvss_version = _extract_cvss(cve.get("metrics", {}))
    return {
        "id": cve.get("id"),
        "description": _pick_description(cve.get("descriptions")),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_version": cvss_version,
    }


def parse_nvd_response(payload):
    """Parse a raw NVD v2.0 JSON payload into a list of normalized CVE dicts."""
    vulnerabilities = payload.get("vulnerabilities", [])
    results = [_parse_cve_item(item) for item in vulnerabilities]
    results.sort(key=lambda r: (r["cvss_score"] is None, -(r["cvss_score"] or 0)))
    return results


def lookup(query, api_key=None, timeout=15):
    """Look up a CVE ID or keyword against NVD. Always returns a dict.

    On success: {"query": ..., "results": [...]}
    On failure: {"query": ..., "error": "..."}
    """
    query = (query or "").strip()
    params = {}
    if _CVE_ID_RE.match(query):
        params["cveId"] = query.upper()
    else:
        params["keywordSearch"] = query

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    _throttle(has_api_key=bool(api_key))

    try:
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return {"query": query, "error": f"Network error contacting NVD: {e}"}

    global _last_request_time
    _last_request_time = time.time()

    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError:
            return {"query": query, "error": "NVD returned an unparsable response"}
        results = parse_nvd_response(payload)
        return {"query": query, "results": results}
    elif response.status_code == 403:
        return {"query": query, "error": "Rate limited by NVD (HTTP 403). Slow down or add an API key."}
    elif response.status_code == 404:
        return {"query": query, "error": "No results found (HTTP 404)."}
    else:
        return {"query": query, "error": f"NVD API error: HTTP {response.status_code}"}
