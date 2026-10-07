"""Pilar 5 — Remediacao sob demanda.

Gera um patch minimo (unified diff) para UM finding usando Sonnet com o arquivo
alvo completo. Persiste em `remediations`. Degrada gracioso se AI indisponivel
ou arquivo nao localizado.
"""
from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.client import AIUnavailableError, get_ai
from app.core.prioritizer import _asset_vars, _load_file_snippet, _resolve_file_path
from app.models import AIAnalysis, Asset, Finding, Remediation
from app.schemas.ai import RemediationOutput

logger = logging.getLogger("aspm.remediator")


def _latest_rationale(db: Session, finding_id) -> str:
    row = db.scalar(
        select(AIAnalysis)
        .where(AIAnalysis.finding_id == finding_id)
        .order_by(AIAnalysis.created_at.desc())
        .limit(1)
    )
    if row is None:
        return "-"
    return (row.rationale or "-")[:2000]


def _run_dast_remediation(
    db: Session, asset: Asset, finding: Finding
) -> tuple[RemediationOutput, dict] | None:
    """Remediacao DAST — nao exige arquivo. Prompt orienta controles HTTP."""
    ai = get_ai()
    prompt_vars = {
        **_asset_vars(asset),
        "finding_id": str(finding.id),
        "rule_id": finding.rule_id or "-",
        "title": finding.title,
        "description": (finding.description or "-")[:1000],
        "severity": finding.severity_raw or "unknown",
        "cwe": ", ".join(finding.cwe or []) or "-",
        "url": finding.url or "-",
        "http_method": finding.http_method or "-",
        "parameter": finding.parameter or "-",
        "evidence": (finding.evidence or "-")[:1000],
        "solution": (finding.solution or "-")[:500],
        "prior_rationale": _latest_rationale(db, finding.id),
    }
    try:
        return ai.call_structured(
            prompt_name="dast_remediation",
            prompt_vars=prompt_vars,
            response_model=RemediationOutput,
            model="claude-sonnet-4-6",
            max_tokens=2048,
        )
    except AIUnavailableError as e:
        logger.warning("remediator dast: finding %s falhou: %s", finding.id, e)
        return None
    except Exception as e:
        logger.exception("remediator dast: finding %s falhou (inesperado): %s", finding.id, e)
        return None


def run_remediation_for_finding(
    db: Session,
    asset: Asset,
    finding: Finding,
    repo_path: Path,
) -> Remediation | None:
    ai = get_ai()
    if not ai.enabled:
        logger.info("remediator: AI desabilitada; pulando")
        return None

    # Branch DAST — nao requer arquivo. Diff pode vir vazio quando nao ha
    # SAST correlacionado; a correcao e descritiva (headers, validacao, auth).
    if finding.category == "dast":
        result = _run_dast_remediation(db, asset, finding)
        if result is None:
            return None
        parsed, telemetry = result
        row = Remediation(
            finding_id=finding.id,
            patch_diff=parsed.patch_diff or None,
            explanation=parsed.explanation,
            breaking_risk=parsed.breaking_risk,
            test_suggestion=parsed.test_suggestion,
            applied=False,
            model=telemetry.get("model", "claude-sonnet-4-6"),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    file_path = _resolve_file_path(repo_path, finding.file_path)
    if file_path is None:
        logger.info(
            "remediator: arquivo nao localizado para %s (%s)",
            finding.id, finding.file_path,
        )
        return None
    try:
        content, line_count = _load_file_snippet(file_path)
    except FileNotFoundError:
        return None

    prompt_vars = {
        **_asset_vars(asset),
        "finding_id": str(finding.id),
        "tool": finding.source_tool,
        "category": finding.category,
        "rule_id": finding.rule_id or "-",
        "title": finding.title,
        "description": (finding.description or "-")[:1000],
        "severity": finding.severity_raw or "unknown",
        "file_path": finding.file_path or "-",
        "line_start": finding.line_start or 0,
        "line_end": finding.line_end or 0,
        "cve": finding.cve or "-",
        "package_name": finding.package_name or "-",
        "package_version": finding.package_version or "-",
        "fixed_version": finding.fixed_version or "-",
        "prior_rationale": _latest_rationale(db, finding.id),
        "file_lines": line_count,
        "file_content": content,
    }

    try:
        parsed, telemetry = ai.call_structured(
            prompt_name="remediation",
            prompt_vars=prompt_vars,
            response_model=RemediationOutput,
            model="claude-sonnet-4-6",
            max_tokens=2048,
        )
    except AIUnavailableError as e:
        logger.warning("remediator: finding %s falhou: %s", finding.id, e)
        return None
    except Exception as e:
        logger.exception("remediator: finding %s falhou (inesperado): %s", finding.id, e)
        return None

    row = Remediation(
        finding_id=finding.id,
        patch_diff=parsed.patch_diff or None,
        explanation=parsed.explanation,
        breaking_risk=parsed.breaking_risk,
        test_suggestion=parsed.test_suggestion,
        applied=False,
        model=telemetry.get("model", "claude-sonnet-4-6"),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
