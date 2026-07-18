from desisherlock.modules import dns_recon


def test_check_spf_found():
    result = dns_recon.check_spf(['"v=spf1 -all"'])
    assert result == {"present": True, "record": "v=spf1 -all", "error": None}


def test_check_spf_found_among_other_txt_records():
    records = ['"google-site-verification=abc123"', '"v=spf1 include:_spf.example.com ~all"']
    result = dns_recon.check_spf(records)
    assert result["present"] is True
    assert result["record"] == "v=spf1 include:_spf.example.com ~all"


def test_check_spf_absent_when_no_records():
    result = dns_recon.check_spf([])
    assert result == {"present": False, "record": None, "error": None}


def test_check_spf_timeout_is_not_confused_with_absent():
    # None means the TXT query timed out (see _resolve_records) - this must
    # NOT be reported the same way as "confirmed no SPF record exists".
    result = dns_recon.check_spf(None)
    assert result["present"] is False
    assert result["error"] is not None


def test_check_spf_handles_split_quoted_chunks():
    # Long TXT values are sometimes rendered as adjacent quoted chunks.
    records = ['"v=spf1 " "include:_spf.example.com " "~all"']
    result = dns_recon.check_spf(records)
    assert result["present"] is True
    assert result["record"] == "v=spf1 include:_spf.example.com ~all"


def test_check_dmarc_parses_policy(monkeypatch):
    monkeypatch.setattr(
        dns_recon, "_resolve_records", lambda *a, **k: ['"v=DMARC1; p=reject; pct=100"']
    )
    result = dns_recon.check_dmarc("example.com")
    assert result["present"] is True
    assert result["policy"] == "reject"
    assert result["error"] is None


def test_check_dmarc_absent(monkeypatch):
    monkeypatch.setattr(dns_recon, "_resolve_records", lambda *a, **k: [])
    result = dns_recon.check_dmarc("example.com")
    assert result == {"present": False, "record": None, "policy": None, "error": None}


def test_check_dmarc_timeout_is_not_confused_with_absent(monkeypatch):
    monkeypatch.setattr(dns_recon, "_resolve_records", lambda *a, **k: None)
    result = dns_recon.check_dmarc("example.com")
    assert result["present"] is False
    assert result["error"] is not None


def test_check_dnssec_published(monkeypatch):
    class FakeAnswers(list):
        pass

    def fake_resolve(self, domain, rtype):
        return FakeAnswers([1, 2, 3])

    monkeypatch.setattr(dns_recon.dns.resolver.Resolver, "resolve", fake_resolve)
    result = dns_recon.check_dnssec("example.com")
    assert result == {"dnskey_published": True, "key_count": 3}


def test_check_dnssec_not_published(monkeypatch):
    def fake_resolve(self, domain, rtype):
        raise dns_recon.dns.resolver.NoAnswer()

    monkeypatch.setattr(dns_recon.dns.resolver.Resolver, "resolve", fake_resolve)
    result = dns_recon.check_dnssec("example.com")
    assert result == {"dnskey_published": False, "key_count": 0}
