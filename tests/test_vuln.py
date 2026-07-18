from unittest import mock

import pytest
import requests

from desisherlock.modules import vuln


def _cve_item(cve_id, descriptions, metrics, published="2021-01-01T00:00:00.000",
              last_modified="2021-01-02T00:00:00.000"):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": last_modified,
            "descriptions": descriptions,
            "metrics": metrics,
        }
    }


class FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json


@pytest.fixture(autouse=True)
def no_throttle_sleep(monkeypatch):
    # Prevent the courtesy rate-limit sleep from slowing down the test suite.
    monkeypatch.setattr(vuln.time, "sleep", lambda *_: None)


def test_score_extraction_v31():
    payload = {
        "vulnerabilities": [
            _cve_item(
                "CVE-2021-44228",
                [{"lang": "en", "value": "Log4Shell"}],
                {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
            )
        ]
    }
    results = vuln.parse_nvd_response(payload)
    assert results[0]["cvss_score"] == 10.0
    assert results[0]["cvss_version"] == "3.1"
    assert results[0]["cvss_severity"] == "CRITICAL"


def test_cvss_version_fallback_order():
    # No v3.1, has v3.0 -> should use v3.0, not fall through to v2.
    payload = {
        "vulnerabilities": [
            _cve_item(
                "CVE-2020-0001",
                [{"lang": "en", "value": "desc"}],
                {
                    "cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                    "cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}],
                },
            )
        ]
    }
    results = vuln.parse_nvd_response(payload)
    assert results[0]["cvss_version"] == "3.0"
    assert results[0]["cvss_score"] == 7.5


def test_cvss_falls_back_to_v2_when_no_v3():
    payload = {
        "vulnerabilities": [
            _cve_item(
                "CVE-2019-0001",
                [{"lang": "en", "value": "desc"}],
                {"cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}]},
            )
        ]
    }
    results = vuln.parse_nvd_response(payload)
    assert results[0]["cvss_version"] == "2.0"
    assert results[0]["cvss_score"] == 5.0


def test_no_metrics_gives_none_score():
    payload = {"vulnerabilities": [_cve_item("CVE-2018-0001", [{"lang": "en", "value": "desc"}], {})]}
    results = vuln.parse_nvd_response(payload)
    assert results[0]["cvss_score"] is None
    assert results[0]["cvss_version"] is None


def test_language_filtering_prefers_english():
    payload = {
        "vulnerabilities": [
            _cve_item(
                "CVE-2021-0001",
                [
                    {"lang": "fr", "value": "Description en francais"},
                    {"lang": "en", "value": "English description"},
                ],
                {"cvssMetricV31": [{"cvssData": {"baseScore": 6.0, "baseSeverity": "MEDIUM"}}]},
            )
        ]
    }
    results = vuln.parse_nvd_response(payload)
    assert results[0]["description"] == "English description"


def test_language_filtering_falls_back_to_first_when_no_english():
    payload = {
        "vulnerabilities": [
            _cve_item(
                "CVE-2021-0002",
                [{"lang": "fr", "value": "Seulement en francais"}],
                {},
            )
        ]
    }
    results = vuln.parse_nvd_response(payload)
    assert results[0]["description"] == "Seulement en francais"


def test_sort_order_highest_score_first():
    payload = {
        "vulnerabilities": [
            _cve_item("CVE-LOW", [{"lang": "en", "value": "low"}],
                      {"cvssMetricV31": [{"cvssData": {"baseScore": 3.0, "baseSeverity": "LOW"}}]}),
            _cve_item("CVE-HIGH", [{"lang": "en", "value": "high"}],
                      {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}),
            _cve_item("CVE-NONE", [{"lang": "en", "value": "none"}], {}),
        ]
    }
    results = vuln.parse_nvd_response(payload)
    ids = [r["id"] for r in results]
    assert ids == ["CVE-HIGH", "CVE-LOW", "CVE-NONE"]


def test_lookup_uses_cve_id_param_for_exact_id():
    with mock.patch.object(vuln.requests, "get", return_value=FakeResponse(200, {"vulnerabilities": []})) as m:
        vuln.lookup("CVE-2021-44228")
        _, kwargs = m.call_args
        assert kwargs["params"] == {"cveId": "CVE-2021-44228"}


def test_lookup_uses_keyword_param_for_non_cve():
    with mock.patch.object(vuln.requests, "get", return_value=FakeResponse(200, {"vulnerabilities": []})) as m:
        vuln.lookup("apache log4j")
        _, kwargs = m.call_args
        assert kwargs["params"] == {"keywordSearch": "apache log4j"}


def test_lookup_403_is_rate_limited_error():
    with mock.patch.object(vuln.requests, "get", return_value=FakeResponse(403)):
        result = vuln.lookup("CVE-2021-44228")
        assert "error" in result
        assert "Rate limited" in result["error"]


def test_lookup_404_is_no_results_error():
    with mock.patch.object(vuln.requests, "get", return_value=FakeResponse(404)):
        result = vuln.lookup("nonexistent-keyword-xyz")
        assert "error" in result
        assert "No results" in result["error"]


def test_lookup_other_status_is_generic_api_error():
    with mock.patch.object(vuln.requests, "get", return_value=FakeResponse(500)):
        result = vuln.lookup("CVE-2021-44228")
        assert "error" in result
        assert "500" in result["error"]


def test_lookup_network_failure_never_raises():
    with mock.patch.object(vuln.requests, "get", side_effect=requests.exceptions.ConnectionError("boom")):
        result = vuln.lookup("CVE-2021-44228")
        assert "error" in result
