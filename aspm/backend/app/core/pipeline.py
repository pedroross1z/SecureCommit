"""Orquestracao do scan: discovery -> collectors paralelos -> normalizer."""
from __future__ import annotations

import logging
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from app.config import settings
from app.core.collectors.base import Collector, CollectorResult
from app.core.collectors.gitleaks import GitleaksCollector
from app.core.collectors.semgrep import SemgrepCollector
from app.core.collectors.trivy import TrivyCollector
from app.core.correlator import correlate_scan
from app.core.discovery import apply_discovery_to_asset, perform_discovery
from app.core.normalizer import upsert_findings
from app.core.prioritizer import run_deep_dives_for_scan, run_triage_scan
from app.db import SessionLocal
from app.models import Asset, Scan
from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.pipeline")


def _make_collectors() -> list[Collector]:
    return [SemgrepCollector(), TrivyCollector(), GitleaksCollector()]


def _run_one(collector: Collector, repo_path: Path) -> CollectorResult:
    start = time.perf_counter()
    try:
        findings = collector.run(repo_path)
        return CollectorResult(
            findings=findings,
            duration_s=round(time.perf_counter() - start, 2),
            ok=True,
        )
    except Exception as e:
        logger.exception("collector %s falhou", collector.name)
        return CollectorResult(
            findings=[],
            duration_s=round(time.perf_counter() - start, 2),
            ok=False,
            error=f"{type(e).__name__}: {e}",
        )


def _repo_workdir(asset_id: UUID) -> Path:
    base = Path(settings.scan_workdir)
    base.mkdir(parents=True, exist_ok=True)
    return base / str(asset_id)


def run_discovery_task(asset_id: str) -> None:
    """BackgroundTask: rodar apenas discovery no asset (POST /assets)."""
    aid = UUID(asset_id)
    db: Session = SessionLocal()
    try:
        asset = db.get(Asset, aid)
        if asset is None:
            logger.warning("asset %s nao encontrado", asset_id)
            return
        workdir = _repo_workdir(aid)
        try:
            result = perform_discovery(asset.repo_url, workdir, name_hint=asset.name)
            apply_discovery_to_asset(db, asset, result)
            logger.info(
                "discovery ok asset=%s ctx=%s crit=%s",
                asset_id, result.context_source,
                result.context.criticality if result.context else None,
            )
        except Exception as e:
            logger.exception("discovery falhou: %s", e)
    finally:
        db.close()


def run_scan_task(asset_id: str, scan_id: str) -> None:
    """BackgroundTask: pipeline completo — discovery se necessario + collectors."""
    aid = UUID(asset_id)
    sid = UUID(scan_id)
    db: Session = SessionLocal()
    try:
        asset = db.get(Asset, aid)
        scan = db.get(Scan, sid)
        if asset is None or scan is None:
            logger.warning("asset/scan nao encontrado: %s / %s", asset_id, scan_id)
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        workdir = _repo_workdir(aid)
        tool_stats: dict[str, dict] = {}

        try:
            result = perform_discovery(asset.repo_url, workdir, name_hint=asset.name)
            apply_discovery_to_asset(db, asset, result)
            scan.commit_sha = result.commit_sha
            repo_path = result.repo_path

            collectors = _make_collectors()
            all_findings: list[RawFinding] = []
            with ThreadPoolExecutor(max_workers=len(collectors)) as pool:
                futures = {pool.submit(_run_one, c, repo_path): c for c in collectors}
                for fut in as_completed(futures, timeout=settings.scanner_timeout_s * 2):
                    c = futures[fut]
                    res: CollectorResult = fut.result()
                    tool_stats[c.name] = {
                        "findings": len(res.findings),
                        "duration_s": res.duration_s,
                        "ok": res.ok,
                        "error": res.error,
                        "available": True,
                    }
                    if res.ok:
                        all_findings.extend(res.findings)

            new, updated = upsert_findings(db, asset.id, scan.id, all_findings)
            tool_stats["_normalizer"] = {"new": new, "updated": updated}

            corr = correlate_scan(db, asset.id, scan.id)
            tool_stats["_correlator"] = {
                "batches": corr.batches,
                "clusters": corr.clusters,
                "clustered_findings": corr.clustered_findings,
                "ai_calls_ok": corr.ai_calls_ok,
                "ai_calls_failed": corr.ai_calls_failed,
                "input_tokens": corr.input_tokens,
                "output_tokens": corr.output_tokens,
            }

            triage = run_triage_scan(db, asset.id, scan.id)
            run_deep_dives_for_scan(db, asset.id, scan.id, repo_path, triage)
            tool_stats["_prioritizer"] = {
                "triage_batches": triage.batches,
                "triage_analyses": triage.analyses_created,
                "triage_ai_ok": triage.ai_calls_ok,
                "triage_ai_failed": triage.ai_calls_failed,
                "deep_dives": triage.deep_dives,
                "deep_ok": triage.deep_ok,
                "deep_failed": triage.deep_failed,
                "input_tokens": triage.input_tokens,
                "output_tokens": triage.output_tokens,
            }

            scan.tool_stats = tool_stats
            scan.status = "done"
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            logger.info(
                "scan %s done: %d findings, %d cluster(s), %d triados, %d deep",
                scan_id, new + updated, corr.clusters,
                triage.analyses_created, triage.deep_ok,
            )
        except Exception as e:
            logger.exception("scan pipeline falhou")
            scan.status = "failed"
            scan.error = f"{type(e).__name__}: {e}"[:2000]
            scan.finished_at = datetime.now(timezone.utc)
            scan.tool_stats = tool_stats
            db.commit()
        finally:
            # Nao apaga o workdir: util para IA de arquivo completo em fases posteriores
            pass
    finally:
        db.close()


def cleanup_workdir(asset_id: str) -> None:
    workdir = _repo_workdir(UUID(asset_id))
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
