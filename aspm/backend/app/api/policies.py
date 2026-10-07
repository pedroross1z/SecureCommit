"""Endpoints de policies: listar, ver detalhe e avaliar contra ultimo scan."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.policy import (
    Policy,
    PolicyEvaluation,
    evaluate_policy,
    list_policies,
    load_policy,
)
from app.db import get_db
from app.models import Asset

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[Policy])
def get_policies() -> list[Policy]:
    return list_policies()


@router.get("/{name}", response_model=Policy)
def get_policy(name: str) -> Policy:
    try:
        return load_policy(name)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e


@router.post("/{name}/evaluate", response_model=PolicyEvaluation)
def evaluate(
    name: str,
    asset_id: UUID = Query(..., description="asset a avaliar"),
    scan_id: UUID | None = Query(default=None, description="scan especifico; default = ultimo 'done'"),
    db: Session = Depends(get_db),
) -> PolicyEvaluation:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset nao encontrado")
    try:
        policy = load_policy(name)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return evaluate_policy(db, asset_id, policy, scan_id=scan_id)
