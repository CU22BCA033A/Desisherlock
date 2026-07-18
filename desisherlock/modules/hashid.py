"""Hash format identification only - no cracking, no wordlists, no brute force."""
import re

_HEX_LENGTHS = {
    32: "MD5 (or NTLM/MD4 - same length, context-dependent)",
    40: "SHA-1",
    56: "SHA-224",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}

_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


def identify(value):
    """Return a list of possible hash-format matches for the given string.

    Never attempts to crack, brute-force, or dictionary-attack the hash -
    this only classifies its *format* by length, charset, and prefix.
    """
    value = value.strip()
    matches = []

    if not value:
        return matches

    if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
        if re.match(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", value):
            matches.append({"format": "bcrypt", "confidence": "high"})
        return matches

    if value.startswith("$6$"):
        if re.match(r"^\$6\$[^$]*\$[./A-Za-z0-9]{86}$", value):
            matches.append({"format": "Unix crypt SHA-512 ($6$)", "confidence": "high"})
        return matches

    if value.startswith("$5$"):
        if re.match(r"^\$5\$[^$]*\$[./A-Za-z0-9]{43}$", value):
            matches.append({"format": "Unix crypt SHA-256 ($5$)", "confidence": "high"})
        return matches

    if value.startswith("$1$"):
        if re.match(r"^\$1\$[^$]*\$[./A-Za-z0-9]{22}$", value):
            matches.append({"format": "Unix crypt MD5 ($1$)", "confidence": "high"})
        return matches

    if value.startswith("pbkdf2_sha"):
        if re.match(r"^pbkdf2_sha(1|256)\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$", value):
            matches.append({"format": "Django PBKDF2", "confidence": "high"})
        return matches

    # Plain hex digest - classify purely by length; several algorithms can
    # share a length, so report all plausible candidates.
    if _HEX_RE.match(value):
        length = len(value)
        if length in _HEX_LENGTHS:
            matches.append({"format": _HEX_LENGTHS[length], "confidence": "medium"})
        return matches

    return matches


def identify_result(value):
    matches = identify(value)
    return {
        "input": value,
        "matches": matches,
        "identified": len(matches) > 0,
    }
