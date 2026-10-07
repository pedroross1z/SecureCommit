"""Testes do correlator — IA mockada, sqlite em memoria."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import Asset, Cluster, Finding, Scan
from app.schemas.ai import ClusterProposal, ClusterResponse


@pytest.fixture()
def db() -> Session:
    # Import tardio garante que os models estao registrados no metadata
    from app import models  # noqa: F401

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    s = SessionMaker()
    try:
        yield s
    finally:
        s.close()


def _make_asset(db: Session) -> Asset:
    a = Asset(repo_url=f"https://x/{uuid.uuid4()}", name="svc", criticality_source="unknown")
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _make_scan(db: Session, asset_id) -> Scan:
    s = Scan(asset_id=asset_id, status="running", started_at=datetime.now(timezone.utc))
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _make_finding(db: Session, asset_id, scan_id, **over) -> Finding:
    base = dict(
        asset_id=asset_id,
        scan_id=scan_id,
        source_tool="semgrep",
        category="sast",
        rule_id="python.sqli",
        title="SQLi",
        file_path="app/a.py",
        fingerprint=uuid.uuid4().hex,
        status="open",
    )
    base.update(over)
    f = Finding(**base)
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def test_correlator_skips_when_less_than_two_findings(db):
    from app.core.correlator import correlate_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    _make_finding(db, a.id, s.id)

    stats = correlate_scan(db, a.id, s.id)
    assert stats.clusters == 0
    assert stats.ai_calls_ok == 0


def test_correlator_skips_when_ai_disabled(db):
    from app.core.correlator import correlate_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    _make_finding(db, a.id, s.id, file_path="a.py")
    _make_finding(db, a.id, s.id, file_path="b.py", fingerprint=uuid.uuid4().hex)

    class _StubAI:
        enabled = False

    with patch("app.core.correlator.get_ai", return_value=_StubAI()):
        stats = correlate_scan(db, a.id, s.id)

    assert stats.clusters == 0
    assert stats.batches == 0


def test_correlator_persists_clusters_and_updates_finding_ids(db):
    from app.core.correlator import correlate_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    f1 = _make_finding(db, a.id, s.id, file_path="app/a.py", fingerprint="fp1")
    f2 = _make_finding(db, a.id, s.id, file_path="app/b.py", fingerprint="fp2")
    f3 = _make_finding(db, a.id, s.id, file_path="app/c.py", fingerprint="fp3")

    response = ClusterResponse(
        clusters=[
            ClusterProposal(
                finding_ids=[str(f1.id), str(f2.id)],
                root_cause="sqli em queries nao parametrizadas",
                confidence=0.9,
            )
        ]
    )

    class _StubAI:
        enabled = True

        def call_structured(self, **_kw):
            return response, {"input_tokens": 100, "output_tokens": 50, "cached": False}

    with patch("app.core.correlator.get_ai", return_value=_StubAI()):
        stats = correlate_scan(db, a.id, s.id)

    assert stats.clusters == 1
    assert stats.clustered_findings == 2
    assert stats.ai_calls_ok == 1
    assert stats.input_tokens == 100

    db.refresh(f1); db.refresh(f2); db.refresh(f3)
    assert f1.cluster_id is not None
    assert f1.cluster_id == f2.cluster_id
    assert f3.cluster_id is None

    cluster = db.get(Cluster, f1.cluster_id)
    assert cluster is not None
    assert cluster.root_cause.startswith("sqli")
    assert float(cluster.confidence) == 0.9


def test_correlator_ignores_hallucinated_ids(db):
    from app.core.correlator import correlate_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    f1 = _make_finding(db, a.id, s.id, fingerprint="fp1", file_path="a.py")
    f2 = _make_finding(db, a.id, s.id, fingerprint="fp2", file_path="b.py")

    # Cluster com so 1 id valido (o outro e alucinado) => descartado
    response = ClusterResponse(
        clusters=[
            ClusterProposal(
                finding_ids=[str(f1.id), str(uuid.uuid4())],
                root_cause="x", confidence=0.5,
            )
        ]
    )

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw): return response, {"input_tokens": 0, "output_tokens": 0}

    with patch("app.core.correlator.get_ai", return_value=_StubAI()):
        stats = correlate_scan(db, a.id, s.id)

    assert stats.clusters == 0
    db.refresh(f1); db.refresh(f2)
    assert f1.cluster_id is None
    assert f2.cluster_id is None


def test_correlator_does_not_reprocess_clustered_findings(db):
    from app.core.correlator import correlate_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    # cria um cluster existente + associa f1
    c = Cluster(asset_id=a.id, root_cause="pre", confidence=1.0)
    db.add(c); db.commit(); db.refresh(c)
    f1 = _make_finding(db, a.id, s.id, fingerprint="fp1")
    f1.cluster_id = c.id
    db.commit()

    called = {"n": 0}

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            called["n"] += 1
            return ClusterResponse(clusters=[]), {"input_tokens": 0, "output_tokens": 0}

    with patch("app.core.correlator.get_ai", return_value=_StubAI()):
        stats = correlate_scan(db, a.id, s.id)

    # Sobrou 0 findings sem cluster => nem chega a chamar IA
    assert called["n"] == 0
    assert stats.batches == 0


def test_correlator_batches_large_input(db):
    from app.core.correlator import _BATCH_SIZE, correlate_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    fs = [
        _make_finding(db, a.id, s.id, fingerprint=f"fp{i}", file_path=f"f{i}.py")
        for i in range(_BATCH_SIZE + 5)
    ]

    calls = {"n": 0}

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            calls["n"] += 1
            return ClusterResponse(clusters=[]), {"input_tokens": 1, "output_tokens": 1}

    with patch("app.core.correlator.get_ai", return_value=_StubAI()):
        stats = correlate_scan(db, a.id, s.id)

    assert calls["n"] == 2  # dois batches
    assert stats.batches == 2
    assert all(f.cluster_id is None for f in fs)
