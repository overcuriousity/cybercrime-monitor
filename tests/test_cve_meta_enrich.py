from cybercrime_monitor.enrich.cve_meta import _is_stale, _parse_nvd_cve
from datetime import datetime, timedelta, timezone

from cybercrime_monitor.settings import settings as app_settings


def test_parse_nvd_cve_prefers_v31_over_v30_and_v2():
    raw = {
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
        },
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
    }
    parsed = _parse_nvd_cve(raw)
    assert parsed == {"cvss_score": 9.8, "cvss_severity": "CRITICAL", "cwe_ids": ["CWE-79"]}


def test_parse_nvd_cve_falls_back_to_v2_baseSeverity_on_metric_object():
    raw = {
        "metrics": {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
        },
        "weaknesses": [],
    }
    parsed = _parse_nvd_cve(raw)
    assert parsed["cvss_score"] == 5.0
    assert parsed["cvss_severity"] == "MEDIUM"
    assert parsed["cwe_ids"] == []


def test_parse_nvd_cve_dedupes_multiple_cwe_entries():
    raw = {
        "metrics": {},
        "weaknesses": [
            {"description": [{"value": "CWE-79"}]},
            {"description": [{"value": "CWE-79"}, {"value": "CWE-89"}]},
        ],
    }
    parsed = _parse_nvd_cve(raw)
    assert parsed["cwe_ids"] == ["CWE-79", "CWE-89"]


def test_parse_nvd_cve_no_metrics_no_weaknesses():
    parsed = _parse_nvd_cve({})
    assert parsed == {"cvss_score": None, "cvss_severity": None, "cwe_ids": []}


def test_is_stale_respects_ttl():
    app_settings.cve_meta_cache_ttl_hours = 168
    now = datetime.now(timezone.utc)
    fresh = (now - timedelta(hours=1)).isoformat()
    stale = (now - timedelta(hours=200)).isoformat()
    assert _is_stale(fresh, now=now) is False
    assert _is_stale(stale, now=now) is True


def test_is_stale_treats_unparseable_as_stale():
    assert _is_stale("not-a-timestamp", now=datetime.now(timezone.utc)) is True
    assert _is_stale(None, now=datetime.now(timezone.utc)) is True
