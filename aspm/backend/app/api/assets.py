from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status  # noqa: F401
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.pipeline import run_scan_task
from app.db import get_db
from app.models import AIAnalysis, Asset, Finding, Scan
from app.schemas.api import AssetOut, CreateAssetRequest, ScanOut

router = APIRouter(prefix="/assets", tags=["assets"])


def _asset_to_out(db: Session, asset: Asset) -> AssetOut:
    open_count = db.scalar(
        select(func.count(Finding.id)).where(
            Finding.asset_id == asset.id, Finding.status == "open"
        )
    ) or 0
    max_score = db.scalar(
        select(func.max(AIAnalysis.risk_score))
        .join(Finding, Finding.id == AIAnalysis.finding_id)
        .where(Finding.asset_id == asset.id, Finding.status == "open")
    )
    return AssetOut(
        **{
            "id": asset.id,
            "repo_url": asset.repo_url,
            "name": asset.name,
            "default_branch": asset.default_branch,
            "languages": asset.languages,
            "frameworks": asset.frameworks,
            "criticality": asset.criticality,
            "criticality_source": asset.criticality_source,
            "internet_facing": asset.internet_facing,
            "handles_pii": asset.handles_pii,
            "has_auth": asset.has_auth,
            "ai_rationale": asset.ai_rationale,
            "owner": asset.owner,
            "created_at": asset.created_at,
            "open_findings": open_count,
            "max_risk_score": max_score,
        }
    )


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    body: CreateAssetRequest,
    db: Session = Depends(get_db),
) -> AssetOut:
    url = body.repo_url.strip()
    existing = db.scalar(select(Asset).where(Asset.repo_url == url))
    if existing is not None:
        raise HTTPException(status_code=409, detail="asset ja existe")

    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    asset = Asset(repo_url=url, name=name, criticality_source="unknown")
    db.add(asset)
    db.commit()
    db.refresh(asset)

    # Discovery roda dentro do scan (POST /assets/{id}/scan).
    return _asset_to_out(db, asset)


@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db)) -> list[AssetOut]:
    assets = db.scalars(select(Asset).order_by(Asset.created_at.desc())).all()
    return [_asset_to_out(db, a) for a in assets]


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: UUID, db: Session = Depends(get_db)) -> AssetOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset nao encontrado")
    return _asset_to_out(db, asset)


@router.post("/{asset_id}/scan", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    asset_id: UUID,
    bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset nao encontrado")

    scan = Scan(asset_id=asset_id, status="queued", started_at=datetime.now(timezone.utc))
    db.add(scan)
    db.commit()
    db.refresh(scan)

    bg.add_task(run_scan_task, str(asset_id), str(scan.id))
    return ScanOut.model_validate(scan)
