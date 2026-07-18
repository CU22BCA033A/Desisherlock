"""WHOIS registration lookup.

Uses python-whois (PyPI name), which imports as `whois`. Field access is
defensive (getattr) because different registries return slightly
different shapes - some return a list for dates, some a single value,
some omit fields entirely.
"""
import whois as whois_lib

_FIELDS = [
    "domain_name",
    "registrar",
    "whois_server",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "status",
    "emails",
    "org",
    "country",
]


def _normalize(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return None
    return str(value)


def lookup(domain):
    """Look up WHOIS registration data for a domain. Always returns a dict."""
    domain = domain.strip()
    try:
        record = whois_lib.whois(domain)
    except Exception as e:
        return {"domain": domain, "error": f"WHOIS lookup failed: {e}"}

    if record is None:
        return {"domain": domain, "error": "No WHOIS data returned"}

    result = {"domain": domain}
    for field in _FIELDS:
        result[field] = _normalize(getattr(record, field, None))

    if not any(v for k, v in result.items() if k != "domain"):
        result["error"] = "WHOIS record was empty (domain may not be registered, or registry withheld data)"

    return result
