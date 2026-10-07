"""Endpoints DAST: /api/dast/scans, /api/dast/profiles.

Prefixo nao segue /assets/{id}/dast porque a execucao DAST pode nao usar
o repo_url do asset como alvo (web app em homologacao, dominio custom).
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dast.monitor import (
    enqueue_monitor,
    respider_monitor,
    start_monitor_task,
    stop_monitor,
)
from app.core.dast.profiles import list_profiles
from app.core.dast.service import (
    cancel_dast_scan,
    enqueue_dast_scan,
    run_dast_scan_task,
)
from app.core.dast.ssrf import SSRFError
from app.db import get_db
from app.models import Asset, DastMonitor, DastScan, Finding
from app.schemas.api import (
    CreateDastMonitorRequest,
    CreateDastScanRequest,
    DastMonitorOut,
    DastProfileOut,
    DastScanOut,
    FindingOut,
)

router = APIRouter(prefix="/api/dast", tags=["dast"])


@router.get("/profiles", response_model=list[DastProfileOut])
def get_profiles() -> list[DastProfileOut]:
    return [
        DastProfileOut(
            name=p.name,
            description=p.description,
            requires_authorization=p.requires_authorization,
            default_timeout_s=p.default_timeout_s,
            max_timeout_s=p.max_timeout_s,
        )
        for p in list_profiles()
    ]


@router.post(
    "/scans",
    response_model=DastScanOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_scan(
    body: CreateDastScanRequest,
    bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> DastScanOut:
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset nao encontrado")

    try:
        scan = enqueue_dast_scan(
            db,
            asset_id=asset.id,
            target_url=body.target_url,
            profile_name=body.profile,
            authorized=body.authorized,
            options=body.options,
            requested_by=body.requested_by,
        )
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=f"url bloqueada: {e}") from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    bg.add_task(run_dast_scan_task, str(scan.id))
    return DastScanOut.model_validate(scan)


@router.get("/scans", response_model=list[DastScanOut])
def list_scans(
    asset_id: UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[DastScanOut]:
    stmt = select(DastScan).order_by(DastScan.created_at.desc()).limit(limit)
    if asset_id is not None:
        stmt = stmt.where(DastScan.asset_id == asset_id)
    rows = db.scalars(stmt).all()
    return [DastScanOut.model_validate(r) for r in rows]


@router.get("/scans/{scan_id}", response_model=DastScanOut)
def get_scan(scan_id: UUID, db: Session = Depends(get_db)) -> DastScanOut:
    scan = db.get(DastScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="dast scan nao encontrado")
    return DastScanOut.model_validate(scan)


@router.post("/scans/{scan_id}/cancel", response_model=DastScanOut)
def cancel_scan(scan_id: UUID, db: Session = Depends(get_db)) -> DastScanOut:
    try:
        scan = cancel_dast_scan(db, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return DastScanOut.model_validate(scan)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(scan_id: UUID, db: Session = Depends(get_db)) -> list[FindingOut]:
    scan = db.get(DastScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="dast scan nao encontrado")
    rows = db.scalars(
        select(Finding).where(Finding.dast_scan_id == scan_id)
    ).all()
    return [FindingOut.model_validate(r) for r in rows]


@router.get("/scans/{scan_id}/report")
def scan_report(scan_id: UUID, db: Session = Depends(get_db)) -> dict:
    """Retorna o relatorio JSON bruto do ZAP (se disponivel)."""
    scan = db.get(DastScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="dast scan nao encontrado")
    if not scan.report_path:
        raise HTTPException(status_code=404, detail="relatorio ainda nao disponivel")

    from pathlib import Path

    from app.core.dast.executor import read_report

    path = Path(scan.report_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="arquivo de relatorio ausente")
    try:
        return read_report(path)
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# ---------------------------------------------------------------------------
# Monitors (contínuos)
# ---------------------------------------------------------------------------


@router.post(
    "/monitors",
    response_model=DastMonitorOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_monitor(
    body: CreateDastMonitorRequest,
    bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> DastMonitorOut:
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset nao encontrado")
    try:
        monitor = enqueue_monitor(
            db,
            asset_id=asset.id,
            target_url=body.target_url,
            poll_interval_s=body.poll_interval_s,
            options=body.options,
        )
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=f"url bloqueada: {e}") from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    bg.add_task(start_monitor_task, str(monitor.id))
    return DastMonitorOut.model_validate(monitor)


@router.get("/monitors", response_model=list[DastMonitorOut])
def list_monitors(
    asset_id: UUID | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[DastMonitorOut]:
    stmt = select(DastMonitor).order_by(DastMonitor.created_at.desc())
    if asset_id is not None:
        stmt = stmt.where(DastMonitor.asset_id == asset_id)
    rows = db.scalars(stmt).all()
    return [DastMonitorOut.model_validate(m) for m in rows]


@router.get("/monitors/{monitor_id}", response_model=DastMonitorOut)
def get_monitor(monitor_id: UUID, db: Session = Depends(get_db)) -> DastMonitorOut:
    monitor = db.get(DastMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="monitor nao encontrado")
    return DastMonitorOut.model_validate(monitor)


@router.post("/monitors/{monitor_id}/stop", response_model=DastMonitorOut)
def stop_monitor_endpoint(monitor_id: UUID, db: Session = Depends(get_db)) -> DastMonitorOut:
    try:
        monitor = stop_monitor(db, monitor_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return DastMonitorOut.model_validate(monitor)


@router.post("/monitors/{monitor_id}/respider", response_model=DastMonitorOut)
def respider_monitor_endpoint(
    monitor_id: UUID, db: Session = Depends(get_db)
) -> DastMonitorOut:
    try:
        monitor = respider_monitor(db, monitor_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return DastMonitorOut.model_validate(monitor)


@router.get("/monitors/{monitor_id}/findings", response_model=list[FindingOut])
def monitor_findings(
    monitor_id: UUID, db: Session = Depends(get_db)
) -> list[FindingOut]:
    monitor = db.get(DastMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="monitor nao encontrado")
    rows = db.scalars(
        select(Finding).where(Finding.dast_monitor_id == monitor_id)
        .order_by(Finding.last_seen.desc())
    ).all()
    return [FindingOut.model_validate(r) for r in rows]
