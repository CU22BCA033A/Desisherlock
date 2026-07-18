import http.server
import socket
import socketserver
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from desisherlock.modules import portscan


def test_parse_port_spec_top():
    ports = portscan.parse_port_spec("top")
    assert ports == sorted(set(portscan.TOP_PORTS))


def test_parse_port_spec_default_is_top():
    assert portscan.parse_port_spec(None) == sorted(set(portscan.TOP_PORTS))


def test_parse_port_spec_range():
    assert portscan.parse_port_spec("1-10") == list(range(1, 11))


def test_parse_port_spec_comma_list():
    assert portscan.parse_port_spec("22,80,443") == [22, 80, 443]


def test_parse_port_spec_mixed():
    assert portscan.parse_port_spec("22,100-105,443") == [22, 100, 101, 102, 103, 104, 105, 443]


def test_parse_port_spec_dedupes_and_sorts():
    assert portscan.parse_port_spec("443,80,80,22") == [22, 80, 443]


@pytest.mark.parametrize("spec", ["0-10", "1-70000", "0", "70000", "abc", "22,bad,443"])
def test_parse_port_spec_rejects_out_of_range_or_invalid(spec):
    with pytest.raises(ValueError):
        portscan.parse_port_spec(spec)


def test_parse_port_spec_rejects_inverted_range():
    with pytest.raises(ValueError):
        portscan.parse_port_spec("100-50")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def local_http_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "PytestServer/1.0"

        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    port = _free_port()
    httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    portscan.HTTP_PORTS.add(port)
    yield port
    httpd.shutdown()
    portscan.HTTP_PORTS.discard(port)


def test_check_port_open(local_http_server):
    result = portscan.check_port("127.0.0.1", local_http_server, timeout=1.0, grab_banner=True)
    assert result["state"] == "open"
    assert "PytestServer" in result["banner"]


def test_check_port_closed():
    closed_port = _free_port()  # bound-then-closed - nothing listening
    result = portscan.check_port("127.0.0.1", closed_port, timeout=0.5, grab_banner=False)
    assert result["state"] == "closed"
    assert result["banner"] is None


def test_https_port_skips_plaintext_read():
    note = portscan._grab_banner("127.0.0.1", 443, 0.1)
    assert "ssl" in note.lower()


def test_scan_ports_finds_only_open(local_http_server):
    results = portscan.scan_ports(
        "127.0.0.1", [local_http_server, _free_port()], timeout=0.5, threads=5, grab_banner=True
    )
    assert len(results) == 1
    assert results[0]["port"] == local_http_server


def test_scan_ports_unresolvable_host_reports_error():
    result = portscan.scan_ports(
        "this-host-does-not-exist.invalid.example.nonexistent-tld",
        [80, 443],
        timeout=1.0,
        threads=5,
    )
    assert isinstance(result, dict)
    assert "error" in result


def test_scan_ports_one_flaky_port_does_not_discard_real_open_ports(local_http_server, monkeypatch):
    # Regression test: a real bug found in testing had ANY per-port OSError
    # (e.g. a transient "too many open files" under high concurrency) wipe
    # out the entire scan's results, even ports already confirmed open.
    orig_check_port = portscan.check_port
    call_count = {"n": 0}

    def flaky_check_port(host, port, timeout=1.0, grab_banner=False):
        call_count["n"] += 1
        if call_count["n"] == 3:
            return {"port": port, "state": "error", "service": None,
                     "banner": None, "error": "Too many open files"}
        return orig_check_port(host, port, timeout, grab_banner)

    monkeypatch.setattr(portscan, "check_port", flaky_check_port)
    ports = [local_http_server] + [_free_port() for _ in range(4)]
    results = portscan.scan_ports("127.0.0.1", ports, timeout=0.5, threads=5, grab_banner=True)

    assert isinstance(results, list), "a transient per-port error must not collapse the scan into a bare error dict"
    assert any(r["port"] == local_http_server and r["state"] == "open" for r in results)


def test_check_liveness_survives_error_on_first_port(monkeypatch):
    # Regression test: check_liveness used to bail out with "not alive" the
    # moment the FIRST liveness port hit any error, even if a later port
    # would have connected fine.
    call_order = []

    def fake_check_port(host, port, timeout=1.0, grab_banner=False):
        call_order.append(port)
        if port == portscan.LIVENESS_PORTS[0]:
            return {"port": port, "state": "error", "service": None, "banner": None, "error": "boom"}
        return {"port": port, "state": "open", "service": None, "banner": None}

    monkeypatch.setattr(portscan, "check_port", fake_check_port)
    monkeypatch.setattr(portscan, "_resolve_host", lambda host: None)
    assert portscan.check_liveness("example.com", timeout=0.5) is True
    assert len(call_order) >= 2


def test_service_name_lookup_survives_high_concurrency():
    # socket.getservbyport() wraps a non-thread-safe glibc call. Hammer it
    # from many threads at once (as a real port scan does) and confirm it
    # never raises - regression guard for a real crash found in testing.
    portscan._SERVICE_NAME_CACHE.clear()
    ports = list(range(1, 400))
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(portscan._service_name, p) for p in ports * 3]
        for future in as_completed(futures):
            future.result()  # raises if the worker raised


def test_service_name_known_ports():
    assert portscan._service_name(22) == "ssh"
    assert portscan._service_name(80) == "http"
    assert portscan._service_name(65530) is None
