"""Normalizador DAST: ZAP JSON → RawFinding + fingerprint dedup por instancia."""
from __future__ import annotations

from app.core.dast.normalizer import normalize_zap_report, summarize_report
from app.core.normalizer import compute_fingerprint


_SAMPLE_REPORT = {
    "@version": "2.14.0",
    "site": [
        {
            "@name": "https://alvo.example",
            "alerts": [
                {
                    "pluginid": "40018",
                    "alertRef": "40018",
                    "alert": "SQL Injection",
                    "name": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "3",
                    "desc": "SQLi detectada no parametro q",
                    "solution": "Use prepared statements",
                    "cweid": "89",
                    "wascid": "19",
                    "reference": "https://owasp.org/sqli",
                    "instances": [
                        {
                            "uri": "https://alvo.example/search",
                            "method": "GET",
                            "param": "q",
                            "evidence": "SQL syntax error near ''",
                            "attack": "' OR 1=1--",
                        },
                        {
                            "uri": "https://alvo.example/login",
                            "method": "POST",
                            "param": "username",
                            "evidence": "SQL syntax error",
                        },
                    ],
                },
                {
                    "pluginid": "10038",
                    "alert": "Content Security Policy Header Not Set",
                    "name": "Content Security Policy Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "CSP ausente",
                    "cweid": "693",
                    "instances": [
                        {"uri": "https://alvo.example/", "method": "GET"},
                    ],
                },
            ],
        }
    ],
}


def test_normalize_explodes_instances_into_findings():
    rfs = normalize_zap_report(_SAMPLE_REPORT)
    # SQLi: 2 instancias + CSP: 1 instancia
    assert len(rfs) == 3
    sqli = [r for r in rfs if r.rule_id == "40018"]
    assert len(sqli) == 2
    assert all(r.source_tool == "zap" for r in rfs)
    assert all(r.category == "dast" for r in rfs)


def test_normalize_maps_severity_from_riskcode():
    rfs = normalize_zap_report(_SAMPLE_REPORT)
    severities = {r.rule_id: r.severity_raw for r in rfs}
    assert severities["40018"] == "high"      # riskcode 3
    assert severities["10038"] == "medium"    # riskcode 2


def test_normalize_populates_cwe_and_extra():
    rfs = normalize_zap_report(_SAMPLE_REPORT)
    sqli = next(r for r in rfs if r.rule_id == "40018")
    assert sqli.cwe == ["CWE-89"]
    assert sqli.extra["http_method"] in ("GET", "POST")
    assert sqli.extra["parameter"] in ("q", "username")
    assert sqli.extra["solution"] == "Use prepared statements"
    assert sqli.extra["wascid"] == "19"


def test_normalize_handles_empty_alerts():
    rfs = normalize_zap_report({"@version": "2.14", "site": []})
    assert rfs == []


def test_normalize_handles_missing_instances():
    report = {
        "site": [
            {
                "@name": "https://x",
                "alerts": [
                    {
                        "pluginid": "1",
                        "name": "Info",
                        "riskcode": "0",
                        "instances": [],
                    }
                ],
            }
        ]
    }
    rfs = normalize_zap_report(report)
    assert len(rfs) == 1
    assert rfs[0].severity_raw == "info"


def test_fingerprint_distinguishes_dast_instances():
    """SQLi em /search?q e em /login?username devem gerar fingerprints distintos."""
    rfs = normalize_zap_report(_SAMPLE_REPORT)
    sqli = [r for r in rfs if r.rule_id == "40018"]
    fps = {compute_fingerprint(r) for r in sqli}
    assert len(fps) == 2  # 2 instancias distintas → 2 fingerprints


def test_fingerprint_stable_for_same_dast_instance():
    rfs1 = normalize_zap_report(_SAMPLE_REPORT)
    rfs2 = normalize_zap_report(_SAMPLE_REPORT)
    for a, b in zip(rfs1, rfs2):
        assert compute_fingerprint(a) == compute_fingerprint(b)


def test_summarize_report_counts_by_severity():
    s = summarize_report(_SAMPLE_REPORT)
    assert s["alerts"] == 2
    assert s["by_severity"]["high"] == 1
    assert s["by_severity"]["medium"] == 1
    assert s["unique_urls"] == 3
    assert s["zap_version"] == "2.14.0"
