"""Servico DAST — orquestra executor + normalizer + persistencia + IA.

Fluxo:
1. valida URL (SSRF guard)
2. resolve perfil
3. roda ZAP via Docker
4. parseia relatorio JSON
5. normaliza alertas → RawFinding
6. upsert em findings (reusa normalizer central, deduplicando por fingerprint)
7. dispara triagem Haiku pelos findings do scan DAST

Erros do executor viram scan.status='failed' sem interromper o resto do
pipeline do Secure Commit. Tudo roda em `BackgroundTasks` para nao bloquear
o event loop da API.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dast import executor as zap_exec
from app.core.dast.correlator import correlate_dast_sast
from app.core.dast.normalizer import normalize_zap_report, summarize_report
from app.core.dast.profiles import ProfileSpec, get_profile
from app.core.dast.ssrf import SSRFError, validate_target_url
from app.core.normalizer import upsert_findings
from app.core.prioritizer import run_triage_scan
from app.db import SessionLocal
from app.models import Asset, DastScan, Scan

logger = logging.getLogger("aspm.dast.service")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _set_status(
    db: Session,
    scan: DastScan,
    status: str,
    *,
    error: str | None = None,
    metrics: dict | None = None,
    findings_count: int | None = None,
    report_path: str | None = None,
    zap_version: str | None = None,
    duration_s: int | None = None,
    finished: bool = False,
) -> None:
    scan.status = status
    if error is not None:
        scan.error = error[:2000]
    if metrics is not None:
        scan.metrics = metrics
    if findings_count is not None:
        scan.findings_count = findings_count
    if report_path is not None:
        scan.report_path = report_path
    if zap_version is not None:
        scan.zap_version = zap_version
    if duration_s is not None:
        scan.duration_s = duration_s
    if finished:
        scan.finished_at = _now()
    db.commit()


def run_dast_scan_task(dast_scan_id: str) -> None:
    """BackgroundTask: executa um DAST scan de ponta a ponta."""
    sid = UUID(dast_scan_id)
    db: Session = SessionLocal()
    try:
        scan = db.get(DastScan, sid)
        if scan is None:
            logger.warning("dast scan %s nao encontrado", dast_scan_id)
            return
        asset = db.get(Asset, scan.asset_id)
        if asset is None:
            _set_status(db, scan, "failed", error="asset nao encontrado", finished=True)
            return

        try:
            profile = get_profile(scan.profile)
        except ValueError as e:
            _set_status(db, scan, "failed", error=str(e), finished=True)
            return

        # Autorizacao server-side (nunca confie so no front)
        if profile.requires_authorization and not scan.authorized:
            _set_status(
                db, scan, "failed",
                error=f"perfil {profile.name!r} requer autorizacao explicita",
                finished=True,
            )
            return

        # SSRF guard — permite privado so se o host estiver em DAST_ALLOWLIST_HOSTS.
        options = scan.options or {}
        allow_private = bool(options.get("allow_private", False))
        try:
            validate_target_url(scan.target_url, allow_private=allow_private)
        except SSRFError as e:
            _set_status(db, scan, "failed", error=f"ssrf guard: {e}", finished=True)
            return

        timeout_s = int(options.get("timeout_s") or profile.default_timeout_s)
        timeout_s = min(timeout_s, profile.max_timeout_s)

        scan.started_at = _now()
        scan.status = "running"
        db.commit()

        # Executa o ZAP
        try:
            result = zap_exec.run_zap_scan(
                scan_id=sid,
                target_url=scan.target_url,
                profile=profile,
                timeout_s=timeout_s,
            )
        except zap_exec.ZAPUnavailableError as e:
            _set_status(db, scan, "failed", error=str(e), finished=True)
            return
        except TimeoutError as e:
            _set_status(db, scan, "failed", error=str(e), finished=True)
            return
        except Exception as e:
            logger.exception("dast executor explodiu")
            _set_status(
                db, scan, "failed",
                error=f"{type(e).__name__}: {e}", finished=True,
            )
            return

        if result.report_path is None:
            _set_status(
                db, scan, "failed",
                error=(
                    f"zap terminou sem relatorio (rc={result.returncode})"
                    f"; stderr={result.stderr_tail[:400]}"
                ),
                zap_version=result.zap_version,
                duration_s=result.duration_s,
                finished=True,
            )
            return

        # Parseia e normaliza
        try:
            report = zap_exec.read_report(result.report_path)
        except ValueError as e:
            _set_status(
                db, scan, "failed", error=str(e),
                zap_version=result.zap_version,
                duration_s=result.duration_s, finished=True,
            )
            return

        raws = normalize_zap_report(report)
        metrics = summarize_report(report)

        # Precisamos de um Scan "codigo-fonte" dummy para satisfazer a FK
        # scan_id de Finding (que e NOT NULL). Criamos um Scan "dast-only"
        # com commit_sha=None e tool_stats indicando origem DAST.
        host_scan = Scan(
            asset_id=asset.id,
            status="done",
            started_at=scan.started_at,
            finished_at=_now(),
            tool_stats={"source": "dast", "dast_scan_id": str(sid)},
        )
        db.add(host_scan)
        db.commit()
        db.refresh(host_scan)

        new, updated = upsert_findings(
            db, asset.id, host_scan.id, raws, dast_scan_id=sid,
        )

        # Correlator DAST↔SAST (deterministico, por CWE).
        # Nao bloqueia nem falha o scan — apenas registra stats.
        corr_stats = None
        try:
            corr_stats = correlate_dast_sast(db, asset.id, sid)
        except Exception:
            logger.exception("dast: correlator cross-category falhou (nao fatal)")

        # Triagem IA (Haiku). Falha silenciosa se AI desabilitada.
        try:
            run_triage_scan(db, asset.id, host_scan.id)
        except Exception:
            logger.exception("dast: triagem ia falhou (nao fatal)")

        metrics["new"] = new
        metrics["updated"] = updated
        metrics["executor_rc"] = result.returncode
        if corr_stats is not None:
            metrics["correlator"] = {
                "cwes_examined": corr_stats.cwes_examined,
                "clusters_created": corr_stats.clusters_created,
                "clusters_reused": corr_stats.clusters_reused,
                "dast_findings_linked": corr_stats.dast_findings_linked,
                "sast_findings_linked": corr_stats.sast_findings_linked,
            }
        _set_status(
            db, scan, "completed",
            metrics=metrics,
            findings_count=new + updated,
            report_path=str(result.report_path),
            zap_version=result.zap_version,
            duration_s=result.duration_s,
            finished=True,
        )
        logger.info(
            "dast scan %s completed: %d new, %d updated",
            dast_scan_id, new, updated,
        )
    finally:
        db.close()


def enqueue_dast_scan(
    db: Session,
    *,
    asset_id: UUID,
    target_url: str,
    profile_name: str,
    authorized: bool,
    options: dict | None,
    requested_by: str | None,
) -> DastScan:
    """Cria o registro `dast_scans` em estado 'queued' e devolve-o.

    Validacao server-side de perfil + autorizacao + SSRF (via get_profile +
    validate_target_url). Levanta ValueError/SSRFError se invalido.
    """
    profile = get_profile(profile_name)
    if profile.requires_authorization and not authorized:
        raise ValueError(
            f"perfil {profile.name!r} requer autorizacao explicita "
            f"(payload.authorized=true)"
        )
    options = options or {}
    allow_private = bool(options.get("allow_private", False))
    validate_target_url(target_url, allow_private=allow_private)

    scan = DastScan(
        id=uuid4(),
        asset_id=asset_id,
        target_url=target_url.strip(),
        profile=profile.name,
        status="queued",
        requested_by=(requested_by or "api")[:200],
        authorized=authorized,
        options=options,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def cancel_dast_scan(db: Session, scan_id: UUID) -> DastScan:
    scan = db.get(DastScan, scan_id)
    if scan is None:
        raise ValueError("dast scan nao encontrado")
    if scan.status in ("completed", "failed", "cancelled"):
        return scan
    zap_exec.cancel_scan(scan_id)
    scan.status = "cancelled"
    scan.finished_at = _now()
    db.commit()
    db.refresh(scan)
    return scan
