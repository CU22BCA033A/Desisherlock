"""DNS record enumeration and subdomain brute forcing.

Uses dnspython (import dns.resolver), not the stdlib socket module, since
socket.gethostbyname() only ever gives back A records.
"""
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# dns.resolver transitively imports dns.quic, which - if a same-named
# system-wide `aioquic` package is merely *present* (dnspython only checks
# its version via importlib.metadata, never whether it actually imports
# cleanly) - unconditionally imports it. On systems with a broken system
# aioquic/pyOpenSSL/cryptography chain (seen on a real Kali install), that
# raises AttributeError deep inside a module we never asked for, crashing
# this entire tool before a single DNS query runs. We only ever use plain
# synchronous resolution, never DNS-over-QUIC/HTTPS, so force those optional
# features off before dns.resolver (and therefore dns.quic) ever loads.
import dns._features

dns._features.force("doq", False)
dns._features.force("doh", False)

import dns.resolver
import dns.exception

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

_DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "data", "subdomains.txt")


def _resolve_records(domain, record_type, timeout=5.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return None  # distinguish "timed out" from "no records"


def enumerate_records(domain, timeout=5.0):
    """Look up A/AAAA/MX/TXT/NS/CNAME/SOA records for a domain."""
    records = {}
    for rtype in RECORD_TYPES:
        records[rtype] = _resolve_records(domain, rtype, timeout=timeout)
    return {"domain": domain, "records": records}


def _unquote_txt(txt_record):
    """dnspython renders TXT records with surrounding double quotes and may
    split long values into adjacent quoted chunks - join and strip them so
    substring checks like 'v=spf1' work regardless of formatting."""
    return "".join(part.strip('"') for part in txt_record.split('" "'))


def check_spf(txt_records):
    """Find an SPF record among already-resolved TXT records (RFC 7208).

    Returns {"present": bool, "record": str|None, "error": str|None}.
    Apex-domain TXT lookups can legitimately time out (large TXT record
    sets - SPF plus assorted verification strings - can get truncated
    over UDP and need a TCP retry that some networks block), so a timeout
    is reported as an explicit error rather than silently treated the same
    as "no SPF record exists" - those are different facts and conflating
    them would be a real accuracy bug, not just a missing feature.
    """
    if txt_records is None:
        return {"present": False, "record": None, "error": "TXT query timed out - SPF presence unknown"}
    for record in txt_records:
        unquoted = _unquote_txt(record)
        if unquoted.lower().startswith("v=spf1"):
            return {"present": True, "record": unquoted, "error": None}
    return {"present": False, "record": None, "error": None}


def check_dmarc(domain, timeout=5.0):
    """Query _dmarc.<domain> TXT for a DMARC policy record (RFC 7489).

    Returns {"present": bool, "record": str|None, "policy": str|None,
    "error": str|None}. `policy` is the raw p= value
    (none/quarantine/reject) when present. A query timeout is reported via
    `error` rather than silently treated as "no DMARC record".
    """
    txt_records = _resolve_records(f"_dmarc.{domain}", "TXT", timeout=timeout)
    result = {"present": False, "record": None, "policy": None, "error": None}
    if txt_records is None:
        result["error"] = "TXT query timed out - DMARC presence unknown"
        return result
    if not txt_records:
        return result
    for record in txt_records:
        unquoted = _unquote_txt(record)
        if unquoted.lower().startswith("v=dmarc1"):
            result["present"] = True
            result["record"] = unquoted
            for tag in unquoted.split(";"):
                tag = tag.strip()
                if tag.lower().startswith("p="):
                    result["policy"] = tag.split("=", 1)[1].strip()
            return result
    return result


def check_dnssec(domain, timeout=5.0):
    """Check whether `domain` publishes DNSKEY records.

    This confirms the zone has signing keys published - a real, direct DNS
    query, not a guess - but it is NOT full chain-of-trust validation (that
    would require walking DS records up to the root). Reported as
    `dnskey_published`, named precisely so it isn't mistaken for a full
    DNSSEC validation result.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        return {"dnskey_published": True, "key_count": len(answers)}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return {"dnskey_published": False, "key_count": 0}
    except dns.exception.Timeout:
        return {"dnskey_published": None, "key_count": None, "error": "DNSKEY query timed out"}


def _load_wordlist(path=None):
    path = path or _DEFAULT_WORDLIST
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _try_subdomain(word, domain, timeout):
    fqdn = f"{word}.{domain}"
    result = _resolve_records(fqdn, "A", timeout=timeout)
    if result:
        return fqdn, result
    return None


def brute_force_subdomains(domain, wordlist_path=None, threads=50, timeout=3.0):
    """Thread subdomain resolution against a wordlist. Returns found FQDNs."""
    words = _load_wordlist(wordlist_path)
    found = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = [executor.submit(_try_subdomain, w, domain, timeout) for w in words]
        for future in as_completed(futures):
            result = future.result()
            if result:
                fqdn, addresses = result
                found.append({"subdomain": fqdn, "addresses": addresses})

    found.sort(key=lambda r: r["subdomain"])
    return found


def recon(domain, wordlist_path=None, threads=50, timeout=5.0):
    """-dns: full record enumeration + subdomain brute force + email/DNSSEC posture."""
    result = enumerate_records(domain, timeout=timeout)
    result["spf"] = check_spf(result["records"].get("TXT"))
    result["dmarc"] = check_dmarc(domain, timeout=timeout)
    result["dnssec"] = check_dnssec(domain, timeout=timeout)
    result["subdomains"] = brute_force_subdomains(
        domain, wordlist_path=wordlist_path, threads=threads, timeout=min(timeout, 3.0)
    )
    return result
