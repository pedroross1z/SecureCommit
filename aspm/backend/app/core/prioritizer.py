"""Pilar 4 — Priorização em 2 estágios.

Estagio 1: triagem em lote com Haiku (rapido, barato) — todos os findings.
Estagio 2: deep-dive com Sonnet e arquivo completo — apenas findings
borderline/alto risco.

risk_score (0-100) e derivado deterministicamente da triagem + criticidade do
asset. E recalculado sempre que houver nova AIAnalysis.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.client import AIUnavailableError, get_ai
from app.models import AIAnalysis, Asset, Finding
from app.schemas.ai import DeepAnalysisResult, TriageBatch, TriageResult

logger = logging.getLogger("aspm.prioritizer")

_TRIAGE_BATCH_SIZE = 15
_SNIPPET_MAX = 300
_FILE_MAX_BYTES = 60_000   # ~60KB de arquivo entra no prompt Sonnet
_MAX_FILE_LINES = 1500

# Quantos findings escalar pro estagio 2 por scan (limite de custo).
_DEEP_TOP_K = 5

_SEVERITY_BASE = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 25,
    "info": 10,
    "unknown": 30,
}

_REACHABILITY_FACTOR = {
    "reachable": 1.0,
    "unknown": 0.8,
    "unreachable": 0.3,
}

_FP_MULTIPLIER = 0.3


@dataclass
class TriageStats:
    batches: int = 0
    analyses_created: int = 0
    ai_calls_ok: int = 0
    ai_calls_failed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    deep_dives: int = 0
    deep_ok: int = 0
    deep_failed: int = 0


def compute_risk_score(
    *,
    severity_raw: str | None,
    reachability: str | None,
    exploitability: int | None,
    business_impact: int | None,
    is_likely_false_positive: bool | None,
    asset_criticality: int | None,
) -> int:
    """Risk score 0-100. Determistico dado os inputs.

    Formula: base(severity) * factor((expl+impact+crit)/15) * reachability_factor
    Reduz para 30% se marcado como provavel FP.
    """
    sev = (severity_raw or "unknown").lower()
    base = _SEVERITY_BASE.get(sev, _SEVERITY_BASE["unknown"])

    expl = exploitability if exploitability is not None else 3
    impact = business_impact if business_impact is not None else 3
    crit = asset_criticality if asset_criticality is not None else 3
    # cada um 1-5, soma 3-15 => factor 0.2 a 1.0
    factor = max(0.2, min(1.0, (expl + impact + crit) / 15))

    reach = (reachability or "unknown").lower()
    rf = _REACHABILITY_FACTOR.get(reach, 0.8)

    score = base * factor * rf
    if is_likely_false_positive:
        score *= _FP_MULTIPLIER

    return max(0, min(100, int(round(score))))


def should_deep_analyze(
    *,
    risk_score: int,
    confidence: float | None,
    is_likely_false_positive: bool | None,
    reachability: str | None,
) -> bool:
    """Escala pro estagio 2 se: risco relevante e triagem incerta ou nao-FP.

    - Nao escala se ja marcado como FP com confianca alta.
    - Escala se risco alto (>=60) e nao e FP obvio.
    - Escala se confianca baixa (<0.65) e reachability nao e claramente unreachable.
    """
    conf = confidence if confidence is not None else 0.5
    if is_likely_false_positive and conf >= 0.8:
        return False
    if (reachability or "").lower() == "unreachable" and conf >= 0.8:
        return False
    if risk_score >= 60 and not is_likely_false_positive:
        return True
    if conf < 0.65 and (reachability or "").lower() != "unreachable":
        return True
    return False


def _finding_to_compact_triage(f: Finding) -> dict:
    snippet = (f.snippet or "")[:_SNIPPET_MAX] or None
    return {
        "id": str(f.id),
        "tool": f.source_tool,
        "category": f.category,
        "rule_id": f.rule_id,
        "severity_raw": f.severity_raw,
        "file": f.file_path,
        "line_start": f.line_start,
        "cve": f.cve,
        "package": f.package_name,
        "package_version": f.package_version,
        "snippet": snippet,
    }


def _finding_to_compact_dast_triage(f: Finding) -> dict:
    """Payload especifico para o prompt dast_triage — expoe campos HTTP."""
    return {
        "id": str(f.id),
        "tool": f.source_tool,
        "rule_id": f.rule_id,
        "title": f.title,
        "severity_raw": f.severity_raw,
        "cwe": f.cwe or [],
        "url": f.url,
        "http_method": f.http_method,
        "parameter": f.parameter,
        "evidence": (f.evidence or "")[:_SNIPPET_MAX] or None,
        "solution": f.solution,
    }


def _asset_vars(asset: Asset) -> dict:
    return {
        "asset_name": asset.name,
        "asset_criticality": asset.criticality or 3,
        "internet_facing": "sim" if asset.internet_facing else "nao",
        "handles_pii": "sim" if asset.handles_pii else "nao",
        "has_auth": "sim" if asset.has_auth else "nao",
        "languages": ", ".join((asset.languages or {}).keys()) or "desconhecido",
    }


def _persist_triage(
    db: Session,
    finding: Finding,
    tr: TriageResult,
    asset_criticality: int | None,
    model: str,
    prompt_version: str,
    tokens_in: int,
    tokens_out: int,
) -> AIAnalysis:
    score = compute_risk_score(
        severity_raw=finding.severity_raw,
        reachability=tr.reachability,
        exploitability=tr.exploitability,
        business_impact=tr.business_impact,
        is_likely_false_positive=tr.is_likely_false_positive,
        asset_criticality=asset_criticality,
    )
    row = AIAnalysis(
        finding_id=finding.id,
        reachability=tr.reachability,
        exploitability=tr.exploitability,
        business_impact=tr.business_impact,
        risk_score=score,
        is_likely_false_positive=tr.is_likely_false_positive,
        confidence=round(float(tr.confidence), 2),
        rationale=tr.rationale[:5000],
        model=model,
        prompt_version=prompt_version,
        input_tokens=tokens_in,
        output_tokens=tokens_out,
    )
    db.add(row)
    return row


def _batches(items: list[Finding], size: int) -> list[list[Finding]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _run_triage_batch(
    db: Session,
    *,
    asset: Asset,
    batch: list[Finding],
    by_id: dict[str, Finding],
    prompt_name: str,
    payload_fn,
    stats: TriageStats,
) -> None:
    """Executa UM batch de triagem com o prompt indicado."""
    ai = get_ai()
    stats.batches += 1
    payload = [payload_fn(f) for f in batch]
    try:
        parsed, telemetry = ai.call_structured(
            prompt_name=prompt_name,
            prompt_vars={
                **_asset_vars(asset),
                "findings_json": json.dumps(payload, ensure_ascii=False),
            },
            response_model=TriageBatch,
            model="claude-haiku-4-5",
            max_tokens=2048,
        )
    except AIUnavailableError as e:
        stats.ai_calls_failed += 1
        logger.warning(
            "prioritizer: triagem batch %d (%s) falhou: %s",
            stats.batches, prompt_name, e,
        )
        return
    except Exception as e:
        stats.ai_calls_failed += 1
        logger.exception(
            "prioritizer: triagem batch %d (%s) falhou (inesperado): %s",
            stats.batches, prompt_name, e,
        )
        return

    stats.ai_calls_ok += 1
    stats.input_tokens += telemetry.get("input_tokens", 0) or 0
    stats.output_tokens += telemetry.get("output_tokens", 0) or 0

    for tr in parsed.results:
        f = by_id.get(tr.finding_id)
        if f is None:
            continue  # alucinacao
        _persist_triage(
            db, f, tr,
            asset_criticality=asset.criticality,
            model=telemetry.get("model", "claude-haiku-4-5"),
            prompt_version=telemetry.get("prompt_version", "v0"),
            tokens_in=telemetry.get("input_tokens", 0) or 0,
            tokens_out=telemetry.get("output_tokens", 0) or 0,
        )
        stats.analyses_created += 1

    db.commit()


def run_triage_scan(db: Session, asset_id: UUID, scan_id: UUID) -> TriageStats:
    """Estagio 1: triagem em lote de todos os findings do scan.

    Roteia findings por categoria para o prompt apropriado:
    - `category='dast'` → prompt `dast_triage` (sinais HTTP, sem snippet de codigo)
    - restante → prompt `triage` (sinais estaticos: regra, arquivo, snippet)

    Cria uma AIAnalysis por finding. Degrada silencioso se AI indisponivel.
    """
    stats = TriageStats()

    asset = db.get(Asset, asset_id)
    if asset is None:
        logger.warning("prioritizer: asset %s nao encontrado", asset_id)
        return stats

    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.category, Finding.severity_raw.desc().nulls_last())
        ).all()
    )
    if not findings:
        return stats

    ai = get_ai()
    if not ai.enabled:
        logger.info("prioritizer: AI desabilitada; pulando triagem")
        return stats

    by_id: dict[str, Finding] = {str(f.id): f for f in findings}

    dast_findings = [f for f in findings if f.category == "dast"]
    code_findings = [f for f in findings if f.category != "dast"]

    for batch in _batches(code_findings, _TRIAGE_BATCH_SIZE):
        _run_triage_batch(
            db, asset=asset, batch=batch, by_id=by_id,
            prompt_name="triage",
            payload_fn=_finding_to_compact_triage,
            stats=stats,
        )

    for batch in _batches(dast_findings, _TRIAGE_BATCH_SIZE):
        _run_triage_batch(
            db, asset=asset, batch=batch, by_id=by_id,
            prompt_name="dast_triage",
            payload_fn=_finding_to_compact_dast_triage,
            stats=stats,
        )

    return stats


def _resolve_file_path(repo_path: Path, finding_file: str | None) -> Path | None:
    """Localiza o arquivo do finding: pode vir relativo ou absoluto do scanner."""
    if not finding_file:
        return None
    p = Path(finding_file)
    if p.is_absolute() and p.exists():
        return p
    candidate = repo_path / finding_file
    if candidate.exists():
        return candidate
    # Alguns scanners retornam o caminho com o prefixo do repo_path duplicado.
    try:
        rel = p.relative_to(repo_path) if p.is_absolute() else p
        alt = repo_path / rel
        if alt.exists():
            return alt
    except ValueError:
        pass
    return None


def _load_file_snippet(path: Path) -> tuple[str, int]:
    """Le arquivo com limites de bytes/linhas. Retorna (conteudo, linhas)."""
    try:
        data = path.read_bytes()
    except OSError as e:
        raise FileNotFoundError(str(e)) from e
    if len(data) > _FILE_MAX_BYTES:
        data = data[:_FILE_MAX_BYTES]
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > _MAX_FILE_LINES:
        lines = lines[:_MAX_FILE_LINES]
    return "\n".join(lines), len(lines)


def _run_dast_deep_analysis(
    asset: Asset, finding: Finding
) -> tuple[DeepAnalysisResult, dict] | None:
    """Deep analysis DAST — nao usa arquivo, so evidencia HTTP."""
    ai = get_ai()
    prompt_vars = {
        **_asset_vars(asset),
        "finding_id": str(finding.id),
        "tool": finding.source_tool,
        "category": finding.category,
        "rule_id": finding.rule_id or "-",
        "title": finding.title,
        "description": (finding.description or "-")[:1000],
        "severity": finding.severity_raw or "unknown",
        "confidence_zap": "-",  # ZAP confidence vem em alert.confidence; nao
                                 # persistido como coluna — mantem placeholder
        "cwe": ", ".join(finding.cwe or []) or "-",
        "url": finding.url or "-",
        "http_method": finding.http_method or "-",
        "parameter": finding.parameter or "-",
        "evidence": (finding.evidence or "-")[:1000],
        "attack": "-",  # nao persistido; placeholder
        "solution": (finding.solution or "-")[:500],
    }
    try:
        return ai.call_structured(
            prompt_name="dast_deep_analysis",
            prompt_vars=prompt_vars,
            response_model=DeepAnalysisResult,
            model="claude-sonnet-4-6",
            max_tokens=1024,
        )
    except AIUnavailableError as e:
        logger.warning("deep analysis dast: finding %s falhou: %s", finding.id, e)
        return None
    except Exception as e:
        logger.exception("deep analysis dast: finding %s falhou (inesperado): %s", finding.id, e)
        return None


def run_deep_analysis_for_finding(
    db: Session,
    asset: Asset,
    finding: Finding,
    repo_path: Path,
) -> AIAnalysis | None:
    """Estagio 2: deep-dive com Sonnet. Roteia por categoria:
    - DAST: sem arquivo, so evidencia HTTP (prompt dast_deep_analysis)
    - demais: arquivo completo (prompt deep_analysis)
    """
    ai = get_ai()
    if not ai.enabled:
        logger.info("prioritizer: AI desabilitada; pulando deep analysis")
        return None

    # Branch DAST — nao exige arquivo
    if finding.category == "dast":
        result = _run_dast_deep_analysis(asset, finding)
        if result is None:
            return None
        parsed, telemetry = result
        score = compute_risk_score(
            severity_raw=finding.severity_raw,
            reachability=parsed.reachability,
            exploitability=parsed.exploitability,
            business_impact=parsed.business_impact,
            is_likely_false_positive=parsed.is_likely_false_positive,
            asset_criticality=asset.criticality,
        )
        row = AIAnalysis(
            finding_id=finding.id,
            reachability=parsed.reachability,
            exploitability=parsed.exploitability,
            business_impact=parsed.business_impact,
            risk_score=score,
            is_likely_false_positive=parsed.is_likely_false_positive,
            confidence=round(float(parsed.confidence), 2),
            rationale=parsed.rationale[:5000],
            model=telemetry.get("model", "claude-sonnet-4-6"),
            prompt_version=telemetry.get("prompt_version", "v0"),
            input_tokens=telemetry.get("input_tokens", 0) or 0,
            output_tokens=telemetry.get("output_tokens", 0) or 0,
        )
        db.add(row)
        db.commit()
        return row

    file_path = _resolve_file_path(repo_path, finding.file_path)
    if file_path is None:
        logger.info("deep analysis: arquivo nao localizado para %s (%s)", finding.id, finding.file_path)
        return None
    try:
        content, line_count = _load_file_snippet(file_path)
    except FileNotFoundError:
        return None

    asset_vars = _asset_vars(asset)
    prompt_vars = {
        **asset_vars,
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
        "file_lines": line_count,
        "file_content": content,
    }

    try:
        parsed, telemetry = ai.call_structured(
            prompt_name="deep_analysis",
            prompt_vars=prompt_vars,
            response_model=DeepAnalysisResult,
            model="claude-sonnet-4-6",
            max_tokens=1024,
        )
    except AIUnavailableError as e:
        logger.warning("deep analysis: finding %s falhou: %s", finding.id, e)
        return None
    except Exception as e:
        logger.exception("deep analysis: finding %s falhou (inesperado): %s", finding.id, e)
        return None

    score = compute_risk_score(
        severity_raw=finding.severity_raw,
        reachability=parsed.reachability,
        exploitability=parsed.exploitability,
        business_impact=parsed.business_impact,
        is_likely_false_positive=parsed.is_likely_false_positive,
        asset_criticality=asset.criticality,
    )
    row = AIAnalysis(
        finding_id=finding.id,
        reachability=parsed.reachability,
        exploitability=parsed.exploitability,
        business_impact=parsed.business_impact,
        risk_score=score,
        is_likely_false_positive=parsed.is_likely_false_positive,
        confidence=round(float(parsed.confidence), 2),
        rationale=parsed.rationale[:5000],
        model=telemetry.get("model", "claude-sonnet-4-6"),
        prompt_version=telemetry.get("prompt_version", "v0"),
        input_tokens=telemetry.get("input_tokens", 0) or 0,
        output_tokens=telemetry.get("output_tokens", 0) or 0,
    )
    db.add(row)
    db.commit()
    return row


def run_deep_dives_for_scan(
    db: Session,
    asset_id: UUID,
    scan_id: UUID,
    repo_path: Path,
    stats: TriageStats,
    top_k: int = _DEEP_TOP_K,
) -> None:
    """Escala ate top_k findings do scan pro estagio 2.

    Ordena por risk_score desc e filtra por `should_deep_analyze`. Usa a AIAnalysis
    mais recente de cada finding (da triagem).
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        return

    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all())

    candidates: list[tuple[Finding, AIAnalysis]] = []
    for f in findings:
        latest = db.scalar(
            select(AIAnalysis)
            .where(AIAnalysis.finding_id == f.id)
            .order_by(AIAnalysis.created_at.desc())
            .limit(1)
        )
        if latest is None:
            continue
        if should_deep_analyze(
            risk_score=latest.risk_score or 0,
            confidence=float(latest.confidence) if latest.confidence is not None else None,
            is_likely_false_positive=latest.is_likely_false_positive,
            reachability=latest.reachability,
        ):
            candidates.append((f, latest))

    candidates.sort(key=lambda pair: pair[1].risk_score or 0, reverse=True)
    picked = candidates[:top_k]
    stats.deep_dives = len(picked)

    for f, _ in picked:
        try:
            row = run_deep_analysis_for_finding(db, asset, f, repo_path)
            if row is None:
                stats.deep_failed += 1
            else:
                stats.deep_ok += 1
                stats.input_tokens += row.input_tokens or 0
                stats.output_tokens += row.output_tokens or 0
        except Exception:
            logger.exception("deep analysis raise para finding %s", f.id)
            stats.deep_failed += 1
