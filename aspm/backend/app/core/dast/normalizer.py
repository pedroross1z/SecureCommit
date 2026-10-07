"""Normalizador do relatorio ZAP → RawFinding (category='dast').

Formato ZAP (resumido):
{
  "@version": "2.14.0",
  "site": [
    {
      "@name": "https://alvo",
      "alerts": [
        {
          "pluginid": "40018",
          "alertRef": "40018",
          "alert": "SQL Injection",
          "name": "SQL Injection",
          "riskcode": "3",     # 0=info,1=low,2=medium,3=high
          "confidence": "3",
          "riskdesc": "High (Medium)",
          "desc": "...",
          "solution": "...",
          "cweid": "89",
          "wascid": "19",
          "instances": [
            {"uri": "...", "method": "POST", "param": "q", "evidence": "..."}
          ]
        }
      ]
    }
  ]
}

Explodimos cada `instance` em um RawFinding separado — endpoints distintos
sao achados distintos, com fingerprints distintos.
"""
from __future__ import annotations

import logging
from typing import Any

from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.dast.normalizer")

# riskcode (ZAP) → severidade canonica do Secure Commit.
_RISK_TO_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}


def _risk_to_severity(risk: Any) -> str:
    code = str(risk).strip() if risk is not None else ""
    return _RISK_TO_SEVERITY.get(code, "unknown")


def _cwe_list(cweid: Any) -> list[str]:
    if cweid in (None, "", "-1"):
        return []
    try:
        n = int(str(cweid).strip())
    except (ValueError, TypeError):
        return []
    if n <= 0:
        return []
    return [f"CWE-{n}"]


def _safe_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    return s[:limit]


def normalize_zap_report(report: dict) -> list[RawFinding]:
    """Converte um relatorio ZAP (dict) em RawFindings."""
    findings: list[RawFinding] = []
    sites = report.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_name = site.get("@name") or site.get("name") or ""
        alerts = site.get("alerts") or []
        for alert in alerts:
            rule_id = (
                _safe_text(alert.get("pluginid"), 50)
                or _safe_text(alert.get("alertRef"), 50)
            )
            title = (
                _safe_text(alert.get("name"), 200)
                or _safe_text(alert.get("alert"), 200)
                or "ZAP finding"
            )
            severity = _risk_to_severity(alert.get("riskcode"))
            description = _safe_text(alert.get("desc"), 5000)
            solution = _safe_text(alert.get("solution"), 2000)
            cwe = _cwe_list(alert.get("cweid"))
            reference = _safe_text(alert.get("reference"), 2000)
            wascid = _safe_text(alert.get("wascid"), 20)

            instances = alert.get("instances") or []
            if not instances:
                # alerta sem instancias — ainda vale como finding, sem URL.
                findings.append(
                    RawFinding(
                        source_tool="zap",
                        category="dast",
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity_raw=severity,
                        cwe=cwe,
                        extra={
                            "site": site_name,
                            "solution": solution,
                            "reference": reference,
                            "wascid": wascid,
                            "confidence": _safe_text(alert.get("confidence"), 10),
                        },
                    )
                )
                continue

            for inst in instances:
                uri = _safe_text(inst.get("uri"), 1000) or site_name
                method = _safe_text(inst.get("method"), 10)
                param = _safe_text(inst.get("param"), 200)
                evidence = _safe_text(inst.get("evidence"), 2000)
                attack = _safe_text(inst.get("attack"), 2000)
                findings.append(
                    RawFinding(
                        source_tool="zap",
                        category="dast",
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity_raw=severity,
                        cwe=cwe,
                        # file_path reaproveitado p/ URL: muitas views ja listam por file.
                        # URL "pura" vai no extra pra ser copiada p/ Finding.url pelo upsert.
                        file_path=uri,
                        snippet=(evidence or attack or "")[:1000] or None,
                        extra={
                            "site": site_name,
                            "url": uri,
                            "http_method": method,
                            "parameter": param,
                            "evidence": evidence,
                            "attack": attack,
                            "solution": solution,
                            "reference": reference,
                            "wascid": wascid,
                            "confidence": _safe_text(alert.get("confidence"), 10),
                        },
                    )
                )

    logger.info("dast normalizer: %d findings extraidos", len(findings))
    return findings


def summarize_report(report: dict) -> dict:
    """Metricas rapidas do relatorio ZAP (p/ dast_scans.metrics)."""
    alerts = 0
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    urls: set[str] = set()
    sites = report.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        for alert in site.get("alerts") or []:
            alerts += 1
            sev = _risk_to_severity(alert.get("riskcode"))
            by_sev[sev] = by_sev.get(sev, 0) + 1
            for inst in alert.get("instances") or []:
                uri = inst.get("uri")
                if uri:
                    urls.add(uri)
    return {
        "alerts": alerts,
        "unique_urls": len(urls),
        "by_severity": by_sev,
        "zap_version": report.get("@version"),
    }
