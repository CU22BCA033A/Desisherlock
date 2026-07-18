"""TCP-connect port scanning and banner grabbing.

Deliberately uses socket.connect_ex() only - never raw SYN packets - so
this never needs root/sudo, for any user, ever.
"""
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# A curated "top ports" list rather than scanning all 65535 by default.
TOP_PORTS = [
    7, 20, 21, 22, 23, 25, 37, 42, 43, 53, 67, 68, 69, 70, 79, 80, 81, 88,
    102, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179,
    194, 199, 389, 427, 443, 444, 445, 464, 465, 500, 512, 513, 514, 515,
    520, 521, 540, 548, 554, 587, 593, 623, 631, 636, 639, 646, 691, 860,
    873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080,
    1099, 1194, 1214, 1241, 1311, 1352, 1433, 1434, 1512, 1521, 1524,
    1701, 1720, 1723, 1755, 1812, 1813, 1863, 1900, 2000, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2100, 2222, 2375, 2376, 2483, 2484,
    3000, 3128, 3260, 3268, 3269, 3283, 3306, 3389, 3396, 3689, 3690,
    3703, 3986, 4000, 4045, 4444, 4500, 4567, 4664, 4672, 4899, 5000,
    5001, 5009, 5050, 5051, 5060, 5061, 5093, 5222, 5228, 5269, 5351,
    5353, 5355, 5357, 5432, 5555, 5631, 5632, 5666, 5800, 5900, 5901,
    5985, 5986, 6000, 6001, 6112, 6379, 6443, 6502, 6503, 6646, 6666,
    6667, 6668, 6669, 6689, 6881, 6969, 7000, 7001, 7070, 7071, 7199,
    7443, 7474, 7777, 8000, 8008, 8009, 8080, 8081, 8088, 8090, 8091,
    8140, 8222, 8443, 8500, 8531, 8600, 8649, 8834, 8880, 8888, 9000,
    9001, 9042, 9090, 9091, 9100, 9200, 9418, 9443, 9500, 9999, 10000,
    10001, 10250, 11211, 11371, 12345, 15672, 16992, 16993, 17500, 20000,
    24800, 27017, 27018, 28017, 32768, 32769, 49152, 49153, 49154, 49155,
    49156, 50000, 50070, 54321,
]

# A handful of common ports used for a fast liveness check (-S mode).
LIVENESS_PORTS = [80, 443, 22, 21, 25]

HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 8088, 8090, 8091, 8888, 3000, 5000, 9000}
HTTPS_PORTS = {443, 444, 465, 636, 993, 995, 2083, 2087, 2096, 3389, 5061,
               6443, 7443, 8443, 8531, 9443, 989, 990}

_SERVER_HEADER_RE = re.compile(rb"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


_SERVICE_NAME_CACHE = {}
_SERVICE_NAME_LOCK = threading.Lock()


def _service_name(port):
    """Look up the IANA-registered service name for a port via the system's
    /etc/services database (socket.getservbyport) - authoritative and
    zero-maintenance, rather than a hand-written guess table. Returns None
    if the port has no registered name, instead of guessing.

    glibc's getservbyport() is documented as NOT thread-safe (it uses a
    static internal buffer), and this is called from many concurrent scan
    worker threads. A lock serializes the actual native call - cheap since
    results are cached, so the lock is only ever contended on a cache miss.
    """
    if port in _SERVICE_NAME_CACHE:
        return _SERVICE_NAME_CACHE[port]
    with _SERVICE_NAME_LOCK:
        if port in _SERVICE_NAME_CACHE:
            return _SERVICE_NAME_CACHE[port]
        try:
            name = socket.getservbyport(port, "tcp")
        except (OSError, UnicodeDecodeError, UnicodeError):
            name = None
        _SERVICE_NAME_CACHE[port] = name
        return name


def parse_port_spec(spec):
    """Parse 'top', '1-65535', '22,80,443', or a mix of ranges/commas.

    Returns a sorted list of unique ports. Raises ValueError on bad input
    or ports outside 1-65535.
    """
    if spec is None:
        return sorted(set(TOP_PORTS))

    spec = spec.strip()
    if spec.lower() == "top":
        return sorted(set(TOP_PORTS))

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(f"Invalid port range: '{chunk}'")
            if start > end:
                raise ValueError(f"Invalid port range: '{chunk}' (start > end)")
            for p in (start, end):
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port out of range (1-65535): {p}")
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                raise ValueError(f"Invalid port: '{chunk}'")
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range (1-65535): {p}")
            ports.add(p)

    if not ports:
        raise ValueError("No ports specified")
    return sorted(ports)


def _grab_banner(host, port, timeout):
    """Attempt to grab a service banner. Returns a string or None."""
    if port in HTTPS_PORTS:
        return "TLS port - use -ssl for certificate/cipher inspection instead of a plaintext read"

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in HTTP_PORTS:
                request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                sock.sendall(request)
                data = sock.recv(4096)
                match = _SERVER_HEADER_RE.search(data)
                if match:
                    return match.group(1).decode(errors="replace").strip()
                return None
            else:
                # SSH/FTP/SMTP/POP3/IMAP etc. announce a version banner
                # unprompted - just read what's there.
                data = sock.recv(1024)
                if data:
                    return data.decode(errors="replace").strip()
                return None
    except (socket.timeout, OSError):
        return None


def _resolve_host(host):
    """Resolve `host` once. Raises socket.gaierror if it truly can't be
    resolved - the one failure mode that means every single port check
    would fail identically, so it's worth checking up front rather than
    discovering it independently in every scan thread."""
    socket.getaddrinfo(host, None)


def check_port(host, port, timeout=1.0, grab_banner=False):
    """Check a single port. Returns a dict with state and optional banner.

    Any per-socket failure here (a transient "too many open files" under
    high scan concurrency, a one-off network hiccup, etc.) is reported as
    an inconclusive "error" state for *this port only* - it must never be
    treated as a reason to discard results already found for other ports.
    Hostname-resolution failures are checked once up front in scan_ports()
    instead, since that's the only failure mode that would affect every
    port identically.
    """
    result = {"port": port, "state": "closed", "service": _service_name(port), "banner": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            if code == 0:
                result["state"] = "open"
    except OSError as e:
        result["state"] = "error"
        result["error"] = str(e)
        return result

    if result["state"] == "open" and grab_banner:
        result["banner"] = _grab_banner(host, port, timeout)

    return result


def scan_ports(host, ports, timeout=1.0, threads=100, grab_banner=True):
    """Scan a list of ports concurrently. Returns list of open-port results,
    or a dict with an "error" key only if `host` itself can't be resolved -
    a single flaky port check must never discard ports already found open."""
    try:
        _resolve_host(host)
    except socket.gaierror as e:
        return {"error": str(e), "target": host}

    open_results = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = {
            executor.submit(check_port, host, port, timeout, grab_banner): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_results.append(result)
            # A per-port "error" state (e.g. a transient resource limit)
            # just means that one port's status is unknown - it is not
            # counted as open, but it does not affect any other port.

    open_results.sort(key=lambda r: r["port"])
    return open_results


def check_liveness(host, timeout=1.0):
    """Quick liveness check via TCP connect to a handful of common ports.

    No ICMP - that needs raw sockets, which this tool deliberately avoids.
    A per-port error (e.g. one port being firewalled while another isn't)
    must not short-circuit this as "not alive" - only try every liveness
    port and having none of them come back open means that.
    """
    try:
        _resolve_host(host)
    except socket.gaierror:
        return False
    for port in LIVENESS_PORTS:
        result = check_port(host, port, timeout=timeout, grab_banner=False)
        if result["state"] == "open":
            return True
    return False


def scan(target, timeout=1.0, threads=100):
    """-S/--scan: liveness check + top-ports scan + banner grab."""
    alive = check_liveness(target, timeout=timeout)
    open_ports = scan_ports(target, TOP_PORTS, timeout=timeout, threads=threads, grab_banner=True)
    if isinstance(open_ports, dict) and "error" in open_ports:
        return {"target": target, "alive": alive, "error": open_ports["error"]}
    return {"target": target, "alive": alive or bool(open_ports), "open_ports": open_ports}


def port_scan(target, port_spec="top", timeout=1.0, threads=100):
    """-port/--port-scan: full scan over the requested port spec."""
    ports = parse_port_spec(port_spec)
    open_ports = scan_ports(target, ports, timeout=timeout, threads=threads, grab_banner=True)
    if isinstance(open_ports, dict) and "error" in open_ports:
        return {"target": target, "ports_scanned": len(ports), "error": open_ports["error"]}
    return {
        "target": target,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
    }
