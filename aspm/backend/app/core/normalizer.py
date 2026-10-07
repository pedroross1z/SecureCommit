"""Normalizer: RawFinding -> Finding (dedup por fingerprint)."""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding
from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.normalizer")

_WHITESPACE_RE = re.compile(r"\s+")
# nomes de variaveis locais (heuristica: identificadores minusculos entre limites de palavra)
# aplicado ao snippet pra fingerprint sobreviver a renomeacoes cosmeticas
_IDENT_RE = re.compile(r"\b[a-z_][a-z0-9_]{0,30}\b")


def normalize_snippet(snippet: str | None) -> str:
    if not snippet:
        return ""
    s = _WHITESPACE_RE.sub(" ", snippet).strip().lower()
    # colapsa identificadores locais em placeholder
    s = _IDENT_RE.sub("_", s)
    return s[:512]


def compute_fingerprint(rf: RawFinding) -> str:
    # DAST tem chaves de dedup distintas: tipo+host+rota+parametro, nao snippet.
    if rf.category == "dast":
        extra = rf.extra or {}
        key = "|".join([
            rf.source_tool,
            rf.rule_id or "",
            (extra.get("url") or rf.file_path or ""),
            (extra.get("http_method") or ""),
            (extra.get("parameter") or ""),
            (rf.cwe[0] if rf.cwe else ""),
        ])
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    key = "|".join([
        rf.source_tool,
        rf.rule_id or "",
        rf.file_path or "",
        normalize_snippet(rf.snippet),
        rf.cve or "",
        rf.package_name or "",
        rf.package_version or "",
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def upsert_findings(
    db: Session,
    asset_id,
    scan_id,
    raws: list[RawFinding],
    *,
    dast_scan_id=None,
    dast_monitor_id=None,
) -> tuple[int, int]:
    """Insere ou atualiza findings. Retorna (new, updated).

    `dast_scan_id` opcional: quando passado, popula o relacionamento com a
    execucao DAST que originou os findings.
    """
    new_count = 0
    updated_count = 0
    now = datetime.now(timezone.utc)

    # Dedup dentro do batch (mesmo fingerprint pode aparecer duas vezes)
    seen_fps: set[str] = set()
    unique_raws: list[tuple[str, RawFinding]] = []
    for rf in raws:
        fp = compute_fingerprint(rf)
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        unique_raws.append((fp, rf))

    for fp, rf in unique_raws:
        extra = rf.extra or {}
        dast_url = extra.get("url") if rf.category == "dast" else None
        dast_method = extra.get("http_method") if rf.category == "dast" else None
        dast_param = extra.get("parameter") if rf.category == "dast" else None
        dast_evidence = extra.get("evidence") if rf.category == "dast" else None
        dast_solution = extra.get("solution") if rf.category == "dast" else None

        existing = db.scalar(
            select(Finding).where(Finding.asset_id == asset_id, Finding.fingerprint == fp)
        )
        if existing is not None:
            existing.last_seen = now
            existing.scan_id = scan_id
            if dast_scan_id is not None:
                existing.dast_scan_id = dast_scan_id
            if dast_monitor_id is not None:
                existing.dast_monitor_id = dast_monitor_id
            # Atualiza campos DAST em re-execucoes (evidencia/payload podem mudar).
            if rf.category == "dast":
                if dast_url:
                    existing.url = dast_url[:1000]
                if dast_method:
                    existing.http_method = dast_method[:10]
                if dast_param:
                    existing.parameter = dast_param[:200]
                if dast_evidence:
                    existing.evidence = dast_evidence[:2000]
                if dast_solution:
                    existing.solution = dast_solution[:2000]
            if existing.status == "fixed":
                existing.status = "open"
            updated_count += 1
            continue

        finding = Finding(
            asset_id=asset_id,
            scan_id=scan_id,
            source_tool=rf.source_tool,
            category=rf.category,
            rule_id=rf.rule_id,
            title=rf.title[:500],
            description=(rf.description or "")[:5000] or None,
            severity_raw=rf.severity_raw,
            cwe=rf.cwe or None,
            cve=rf.cve,
            file_path=rf.file_path,
            line_start=rf.line_start,
            line_end=rf.line_end,
            snippet=(rf.snippet or "")[:2000] or None,
            package_name=rf.package_name,
            package_version=rf.package_version,
            fixed_version=rf.fixed_version,
            url=(dast_url or None) and dast_url[:1000],
            http_method=(dast_method or None) and dast_method[:10],
            parameter=(dast_param or None) and dast_param[:200],
            evidence=(dast_evidence or None) and dast_evidence[:2000],
            solution=(dast_solution or None) and dast_solution[:2000],
            dast_scan_id=dast_scan_id,
            dast_monitor_id=dast_monitor_id,
            fingerprint=fp,
            status="open",
            first_seen=now,
            last_seen=now,
        )
        db.add(finding)
        new_count += 1

    db.commit()
    logger.info("normalizer: %d novos, %d atualizados", new_count, updated_count)
    return new_count, updated_count
