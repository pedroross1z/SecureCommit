from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import AIAnalysis, Cluster, Finding
from app.schemas.api import ClusterOut, FindingOut

router = APIRouter(prefix="/clusters", tags=["clusters"])


def _cluster_to_out(db: Session, c: Cluster) -> ClusterOut:
    count = db.scalar(
        select(func.count(Finding.id)).where(Finding.cluster_id == c.id)
    ) or 0
    max_score = db.scalar(
        select(func.max(AIAnalysis.risk_score))
        .join(Finding, Finding.id == AIAnalysis.finding_id)
        .where(Finding.cluster_id == c.id)
    )
    cats = db.scalars(
        select(Finding.category).where(Finding.cluster_id == c.id).distinct()
    ).all()
    tools = db.scalars(
        select(Finding.source_tool).where(Finding.cluster_id == c.id).distinct()
    ).all()
    return ClusterOut(
        id=c.id,
        asset_id=c.asset_id,
        root_cause=c.root_cause,
        confidence=float(c.confidence) if c.confidence is not None else None,
        source=c.source,
        created_at=c.created_at,
        findings_count=int(count),
        max_risk_score=max_score,
        categories=sorted([x for x in cats if x]),
        tools=sorted([x for x in tools if x]),
    )


@router.get("", response_model=list[ClusterOut])
def list_clusters(
    asset_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ClusterOut]:
    stmt = select(Cluster).order_by(Cluster.created_at.desc()).limit(limit)
    if asset_id is not None:
        stmt = stmt.where(Cluster.asset_id == asset_id)
    rows = db.scalars(stmt).all()
    return [_cluster_to_out(db, c) for c in rows]


@router.get("/{cluster_id}", response_model=ClusterOut)
def get_cluster(cluster_id: UUID, db: Session = Depends(get_db)) -> ClusterOut:
    c = db.get(Cluster, cluster_id)
    if c is None:
        raise HTTPException(status_code=404, detail="cluster nao encontrado")
    return _cluster_to_out(db, c)


@router.get("/{cluster_id}/findings", response_model=list[FindingOut])
def cluster_findings(cluster_id: UUID, db: Session = Depends(get_db)) -> list[FindingOut]:
    from app.api.findings import _to_out  # evita import ciclico no topo

    c = db.get(Cluster, cluster_id)
    if c is None:
        raise HTTPException(status_code=404, detail="cluster nao encontrado")
    rows = db.scalars(
        select(Finding).where(Finding.cluster_id == cluster_id).order_by(Finding.last_seen.desc())
    ).all()
    return [_to_out(db, f) for f in rows]
