from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.pipeline import _repo_workdir
from app.core.prioritizer import run_deep_analysis_for_finding
from app.core.remediator import run_remediation_for_finding
from app.db import get_db
from app.models import AIAnalysis, Asset, Finding, Remediation
from app.schemas.api import FindingOut, RemediationOut, UpdateFindingStatusRequest

router = APIRouter(prefix="/findings", tags=["findings"])


def _to_out(db: Session, f: Finding) -> FindingOut:
    ai = db.scalar(
        select(AIAnalysis)
        .where(AIAnalysis.finding_id == f.id)
        .order_by(AIAnalysis.created_at.desc())
        .limit(1)
    )
    data = {
        "id": f.id,
        "asset_id": f.asset_id,
        "scan_id": f.scan_id,
        "source_tool": f.source_tool,
        "category": f.category,
        "rule_id": f.rule_id,
        "title": f.title,
        "description": f.description,
        "severity_raw": f.severity_raw,
        "cwe": f.cwe,
        "cve": f.cve,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "snippet": f.snippet,
        "package_name": f.package_name,
        "package_version": f.package_version,
        "fixed_version": f.fixed_version,
        "fingerprint": f.fingerprint,
        "cluster_id": f.cluster_id,
        "status": f.status,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "risk_score": ai.risk_score if ai else None,
        "ai_rationale": ai.rationale if ai else None,
    }
    return FindingOut.model_validate(data)


@router.get("", response_model=list[FindingOut])
def list_findings(
    asset_id: UUID | None = None,
    scan_id: UUID | None = None,
    category: str | None = None,
    status: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=100),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    stmt = select(Finding)
    if asset_id is not None:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if category is not None:
        stmt = stmt.where(Finding.category == category)
    if status is not None:
        stmt = stmt.where(Finding.status == status)

    if min_score is not None:
        stmt = stmt.join(AIAnalysis, AIAnalysis.finding_id == Finding.id).where(
            AIAnalysis.risk_score >= min_score
        )

    stmt = stmt.order_by(Finding.last_seen.desc()).limit(limit)
    rows = db.scalars(stmt).all()
    return [_to_out(db, f) for f in rows]


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: UUID, db: Session = Depends(get_db)) -> FindingOut:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding nao encontrado")
    return _to_out(db, f)


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding_status(
    finding_id: UUID,
    body: UpdateFindingStatusRequest,
    db: Session = Depends(get_db),
) -> FindingOut:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding nao encontrado")
    f.status = body.status
    db.commit()
    db.refresh(f)
    return _to_out(db, f)


@router.post("/{finding_id}/analyze", response_model=FindingOut)
def analyze_finding(finding_id: UUID, db: Session = Depends(get_db)) -> FindingOut:
    """Roda deep analysis (Sonnet + arquivo completo) sob demanda.

    Requer que o workdir do asset ainda exista (nao foi limpo).
    """
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding nao encontrado")
    asset = db.get(Asset, f.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset do finding nao encontrado")

    repo_path = _repo_workdir(asset.id)
    if not repo_path.exists():
        raise HTTPException(
            status_code=409,
            detail="workdir do asset nao existe; rode POST /assets/{id}/scan primeiro",
        )

    row = run_deep_analysis_for_finding(db, asset, f, repo_path)
    if row is None:
        raise HTTPException(
            status_code=502,
            detail="deep analysis falhou (AI indisponivel ou arquivo nao localizado)",
        )
    db.refresh(f)
    return _to_out(db, f)


@router.post("/{finding_id}/remediate", response_model=RemediationOut)
def remediate_finding(finding_id: UUID, db: Session = Depends(get_db)) -> RemediationOut:
    """Gera um patch (Sonnet) para o finding. Requer workdir do asset."""
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding nao encontrado")
    asset = db.get(Asset, f.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset do finding nao encontrado")

    repo_path = _repo_workdir(asset.id)
    if not repo_path.exists():
        raise HTTPException(
            status_code=409,
            detail="workdir do asset nao existe; rode POST /assets/{id}/scan primeiro",
        )

    row = run_remediation_for_finding(db, asset, f, repo_path)
    if row is None:
        raise HTTPException(
            status_code=502,
            detail="remediacao falhou (AI indisponivel ou arquivo nao localizado)",
        )
    return RemediationOut.model_validate(row)


@router.get("/{finding_id}/remediations", response_model=list[RemediationOut])
def list_remediations(
    finding_id: UUID, db: Session = Depends(get_db)
) -> list[RemediationOut]:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding nao encontrado")
    rows = db.scalars(
        select(Remediation)
        .where(Remediation.finding_id == finding_id)
        .order_by(Remediation.created_at.desc())
    ).all()
    return [RemediationOut.model_validate(r) for r in rows]
