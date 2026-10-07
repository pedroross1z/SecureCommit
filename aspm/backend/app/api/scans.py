from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import AIAnalysis, Finding, Scan
from app.schemas.api import ScanOut

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: UUID, db: Session = Depends(get_db)) -> ScanOut:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan nao encontrado")
    return ScanOut.model_validate(scan)


@router.get("/{scan_id}/ai-usage")
def scan_ai_usage(scan_id: UUID, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan nao encontrado")
    total_in, total_out, calls = db.execute(
        select(
            func.coalesce(func.sum(AIAnalysis.input_tokens), 0),
            func.coalesce(func.sum(AIAnalysis.output_tokens), 0),
            func.count(AIAnalysis.id),
        )
        .join(Finding, Finding.id == AIAnalysis.finding_id)
        .where(Finding.scan_id == scan_id)
    ).one()
    return {
        "scan_id": str(scan_id),
        "ai_calls": int(calls),
        "input_tokens": int(total_in),
        "output_tokens": int(total_out),
    }
