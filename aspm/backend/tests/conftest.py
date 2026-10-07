"""Fixtures compartilhadas para testes de integracao.

A fixture `shared_db` monta um SQLite in-memory com `StaticPool` (todas as
conexoes compartilham a mesma :memory: db), substitui o `engine` e
`SessionLocal` globais do `app.db` E as referencias ja importadas em
`app.core.dast.service`. Com isso:

- O background task do service (que usa `SessionLocal()` interno) grava no
  mesmo banco que a API (que usa `get_db`).
- O TestClient so precisa override do `get_db` do FastAPI.

NOTA: TestClient roda o `BackgroundTasks` sincronamente apos o retorno do
handler, entao nao precisa aguardar — basta checar o estado apos a request.
"""
from __future__ import annotations

from typing import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db as app_db
from app.core.dast import monitor as dast_monitor
from app.core.dast import service as dast_service
from app.db import Base


@pytest.fixture()
def shared_db(monkeypatch) -> Iterator[sessionmaker]:
    """SQLite in-memory compartilhado via StaticPool."""
    from app import models  # noqa: F401 — registra modelos no metadata

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    SessionMaker = sessionmaker(
        bind=engine, autoflush=False, autocommit=False, future=True
    )
    Base.metadata.create_all(engine)

    # Patch engine e SessionLocal globais e as referencias ja importadas.
    monkeypatch.setattr(app_db, "engine", engine)
    monkeypatch.setattr(app_db, "SessionLocal", SessionMaker)
    monkeypatch.setattr(dast_service, "SessionLocal", SessionMaker)
    monkeypatch.setattr(dast_monitor, "SessionLocal", SessionMaker)

    yield SessionMaker

    Base.metadata.drop_all(engine)
    engine.dispose()
