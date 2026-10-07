"""Pilar 3 (Fase 2) — Correlação: agrupa findings por causa raiz via IA."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.client import AIUnavailableError, get_ai
from app.models import Asset, Cluster, Finding
from app.schemas.ai import ClusterResponse

logger = logging.getLogger("aspm.correlator")

# Envia lotes moderados: mais que isso e o prompt fica pesado e a IA satura.
_BATCH_SIZE = 40
# Snippet grande explode tokens sem ganho — 200 chars ja carrega o padrao.
_SNIPPET_MAX = 200


@dataclass
class CorrelationStats:
    batches: int = 0
    clusters: int = 0
    clustered_findings: int = 0
    ai_calls_ok: int = 0
    ai_calls_failed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def _finding_to_compact(f: Finding) -> dict:
    """Compacta um Finding para o prompt (economiza tokens)."""
    snippet = (f.snippet or "")[:_SNIPPET_MAX] or None
    return {
        "id": str(f.id),
        "tool": f.source_tool,
        "category": f.category,
        "rule_id": f.rule_id,
        "file": f.file_path,
        "cve": f.cve,
        "package": f.package_name,
        "snippet": snippet,
    }


def _fetch_findings_for_scan(db: Session, scan_id: UUID) -> list[Finding]:
    """Findings desse scan, ainda sem cluster (evita re-clusterizar antigos)."""
    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan_id, Finding.cluster_id.is_(None))
        .order_by(Finding.category, Finding.source_tool, Finding.file_path)
    )
    return list(db.scalars(stmt).all())


def _batches(items: list[Finding], size: int) -> list[list[Finding]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def correlate_scan(db: Session, asset_id: UUID, scan_id: UUID) -> CorrelationStats:
    """Correlaciona findings do scan e persiste clusters.

    - Se AI indisponível ou não há findings suficientes, retorna stats vazias sem erro.
    - Cada cluster proposto vira um row em `clusters`; os findings referenciados
      recebem `cluster_id` apontando para o novo cluster.
    - Findings fora de qualquer cluster ficam com `cluster_id` NULL (isolados).
    """
    stats = CorrelationStats()

    asset = db.get(Asset, asset_id)
    if asset is None:
        logger.warning("correlator: asset %s nao encontrado", asset_id)
        return stats

    findings = _fetch_findings_for_scan(db, scan_id)
    if len(findings) < 2:
        logger.info("correlator: <2 findings sem cluster; nada a fazer")
        return stats

    ai = get_ai()
    if not ai.enabled:
        logger.info("correlator: AI desabilitada; pulando")
        return stats

    by_id = {str(f.id): f for f in findings}

    for batch in _batches(findings, _BATCH_SIZE):
        stats.batches += 1
        payload = [_finding_to_compact(f) for f in batch]
        try:
            parsed, telemetry = ai.call_structured(
                prompt_name="correlation",
                prompt_vars={
                    "asset_name": asset.name,
                    "findings_json": json.dumps(payload, ensure_ascii=False),
                },
                response_model=ClusterResponse,
                model="claude-haiku-4-5",
                max_tokens=2048,
            )
        except AIUnavailableError as e:
            stats.ai_calls_failed += 1
            logger.warning("correlator: batch %d falhou (AI): %s", stats.batches, e)
            continue
        except Exception as e:
            stats.ai_calls_failed += 1
            logger.exception("correlator: batch %d falhou (inesperado): %s", stats.batches, e)
            continue

        stats.ai_calls_ok += 1
        stats.input_tokens += telemetry.get("input_tokens", 0) or 0
        stats.output_tokens += telemetry.get("output_tokens", 0) or 0

        _persist_clusters(db, asset_id, parsed, by_id, stats)

    logger.info(
        "correlator: %d cluster(s), %d finding(s) agrupados em %d batch(es)",
        stats.clusters, stats.clustered_findings, stats.batches,
    )
    return stats


def _persist_clusters(
    db: Session,
    asset_id: UUID,
    response: ClusterResponse,
    by_id: dict[str, Finding],
    stats: CorrelationStats,
) -> None:
    """Cria rows em `clusters` e atualiza `finding.cluster_id`.

    Ignora silenciosamente:
    - clusters com <2 ids validos (schema ja exige 2, mas a IA pode citar id fora do batch);
    - ids que nao existem no batch (alucinacao).
    """
    for proposal in response.clusters:
        valid_findings = [by_id[fid] for fid in proposal.finding_ids if fid in by_id]
        if len(valid_findings) < 2:
            continue

        cluster = Cluster(
            asset_id=asset_id,
            root_cause=proposal.root_cause[:2000],
            confidence=round(float(proposal.confidence), 2),
            source="ai",
        )
        db.add(cluster)
        db.flush()  # popula cluster.id sem commitar

        for f in valid_findings:
            f.cluster_id = cluster.id

        stats.clusters += 1
        stats.clustered_findings += len(valid_findings)

    db.commit()
