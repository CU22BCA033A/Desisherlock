"""TLS/SSL certificate and cipher inspection.

The single biggest gotcha in this whole tool: ssl.SSLSocket.getpeercert()
silently returns an empty dict whenever verify_mode is CERT_NONE - which is
exactly the mode needed to even connect to a self-signed or expired
certificate, i.e. exactly the certs an assessment tool most needs to
inspect. It fails silently rather than raising, so it's easy to ship this
broken.

The fix: connect once with CERT_NONE, pull the raw DER bytes via
getpeercert(binary_form=True) regardless of trust status, and parse them
ourselves with the cryptography library. Separately, open a second
connection with a normal verifying context purely to determine whether the
cert would pass standard trust validation.
"""
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

EXPIRY_WARNING_DAYS = 30


def _name_to_str(name):
    try:
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return cn[0].value
    except Exception:
        pass
    return name.rfc4514_string()


def _get_san(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _fetch_raw_cert(host, port, timeout):
    """Connect with CERT_NONE and return the raw DER cert bytes + cipher info."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_bytes = tls_sock.getpeercert(binary_form=True)
            cipher = tls_sock.cipher()
            version = tls_sock.version()
    return der_bytes, cipher, version


def _check_trust(host, port, timeout):
    """Second connection with a verifying context to determine trust status."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except ssl.SSLError as e:
        return False, f"TLS error during verification: {e}"
    except OSError as e:
        return False, f"Connection error during verification: {e}"


def inspect(host, port=443, timeout=5.0):
    """Inspect the TLS certificate and connection at host:port.

    Returns a dict; never raises for expected failure modes (unreachable
    host, self-signed/expired cert, handshake failure) - those are
    reported via an "error" key instead.
    """
    result = {"target": f"{host}:{port}"}

    try:
        der_bytes, cipher, tls_version = _fetch_raw_cert(host, port, timeout)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Could not connect: {e}"
        return result
    except ssl.SSLError as e:
        result["error"] = f"TLS handshake failed: {e}"
        return result

    if not der_bytes:
        result["error"] = "Server did not present a certificate"
        return result

    try:
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    except Exception as e:
        result["error"] = f"Could not parse certificate: {e}"
        return result

    result["subject"] = _name_to_str(cert.subject)
    result["issuer"] = _name_to_str(cert.issuer)
    result["not_valid_before"] = cert.not_valid_before_utc.isoformat()
    result["not_valid_after"] = cert.not_valid_after_utc.isoformat()

    days_remaining = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
    result["days_until_expiry"] = days_remaining
    result["expired"] = days_remaining < 0
    result["expires_soon"] = 0 <= days_remaining <= EXPIRY_WARNING_DAYS

    result["serial_number"] = format(cert.serial_number, "x")
    result["subject_alt_names"] = _get_san(cert)
    result["signature_algorithm"] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None

    if cipher:
        result["cipher_name"] = cipher[0]
        result["cipher_protocol"] = cipher[1]
        result["cipher_bits"] = cipher[2]
    result["tls_version"] = tls_version

    trust_verified, trust_error = _check_trust(host, port, timeout)
    result["trust_verified"] = trust_verified
    if not trust_verified:
        result["trust_error"] = trust_error

    return result
