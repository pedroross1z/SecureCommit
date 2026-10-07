"""Normalizador de alerts da ZAP API → RawFinding.

Diferente de `normalizer.py` (que lê o JSON report do zap-baseline.py), aqui
consumimos a REST API do ZAP daemon (`/JSON/core/view/alerts`). O schema de
cada alert é:

{
  "sourceid": "3",
  "other": "",
  "method": "GET",
  "evidence": "...",
  "pluginId": "40018",
  "cweid": "89",
  "confidence": "High",         # string, nao numero
  "wascid": "19",
  "description": "...",
  "messageId": "123",
  "inputVector": "...",
  "url": "https://alvo/x",
  "tags": {...},
  "reference": "...",
  "solution": "...",
  "alert": "SQL Injection",
  "param": "q",
  "attack": "' OR 1=1--",
  "name": "SQL Injection",
  "risk": "High",               # string "Informational"|"Low"|"Medium"|"High"
  "id": "1",
  "alertRef": "40018"
}

Cada alerta aqui ja e uma instancia individual (nao agrupada por pluginId).
"""
from __future__ import annotations

import logging
from typing import Any

from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.dast.api_normalizer")

# ZAP API retorna strings "Informational"|"Low"|"Medium"|"High" (sem "Critical").
_RISK_TO_SEVERITY = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
}


def _safe(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    return s[:limit]


def _risk_to_severity(risk: Any) -> str:
    s = str(risk or "").strip().lower()
    return _RISK_TO_SEVERITY.get(s, "unknown")


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


def normalize_zap_alerts(alerts: list[dict]) -> list[RawFinding]:
    """Converte alerts da API ZAP em RawFindings (category='dast')."""
    findings: list[RawFinding] = []
    for a in alerts or []:
        rule_id = _safe(a.get("pluginId"), 50) or _safe(a.get("alertRef"), 50)
        title = (
            _safe(a.get("name"), 200)
            or _safe(a.get("alert"), 200)
            or "ZAP finding"
        )
        severity = _risk_to_severity(a.get("risk"))
        description = _safe(a.get("description"), 5000)
        solution = _safe(a.get("solution"), 2000)
        cwe = _cwe_list(a.get("cweid"))
        reference = _safe(a.get("reference"), 2000)
        wascid = _safe(a.get("wascid"), 20)

        url = _safe(a.get("url"), 1000)
        method = _safe(a.get("method"), 10)
        param = _safe(a.get("param"), 200)
        evidence = _safe(a.get("evidence"), 2000)
        attack = _safe(a.get("attack"), 2000)
        confidence = _safe(a.get("confidence"), 20)

        findings.append(
            RawFinding(
                source_tool="zap",
                category="dast",
                rule_id=rule_id,
                title=title,
                description=description,
                severity_raw=severity,
                cwe=cwe,
                file_path=url,
                snippet=(evidence or attack or "")[:1000] or None,
                extra={
                    "url": url,
                    "http_method": method,
                    "parameter": param,
                    "evidence": evidence,
                    "attack": attack,
                    "solution": solution,
                    "reference": reference,
                    "wascid": wascid,
                    "confidence": confidence,
                    "source": "zap-api",
                },
            )
        )

    logger.info("api normalizer: %d findings extraidos de %d alerts", len(findings), len(alerts or []))
    return findings


def summarize_alerts(alerts: list[dict]) -> dict:
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    urls: set[str] = set()
    for a in alerts or []:
        sev = _risk_to_severity(a.get("risk"))
        by_sev[sev] = by_sev.get(sev, 0) + 1
        url = a.get("url")
        if url:
            urls.add(url)
    return {
        "alerts": len(alerts or []),
        "unique_urls": len(urls),
        "by_severity": by_sev,
    }
