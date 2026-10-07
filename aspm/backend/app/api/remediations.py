from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Remediation
from app.schemas.api import RemediationOut, UpdateRemediationRequest

router = APIRouter(prefix="/remediations", tags=["remediations"])


@router.get("/{remediation_id}", response_model=RemediationOut)
def get_remediation(remediation_id: UUID, db: Session = Depends(get_db)) -> RemediationOut:
    r = db.get(Remediation, remediation_id)
    if r is None:
        raise HTTPException(status_code=404, detail="remediacao nao encontrada")
    return RemediationOut.model_validate(r)


@router.patch("/{remediation_id}", response_model=RemediationOut)
def update_remediation(
    remediation_id: UUID,
    body: UpdateRemediationRequest,
    db: Session = Depends(get_db),
) -> RemediationOut:
    r = db.get(Remediation, remediation_id)
    if r is None:
        raise HTTPException(status_code=404, detail="remediacao nao encontrada")
    r.applied = body.applied
    db.commit()
    db.refresh(r)
    return RemediationOut.model_validate(r)
