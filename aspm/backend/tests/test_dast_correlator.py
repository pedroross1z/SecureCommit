"""Correlator DAST ↔ SAST (deterministico, por CWE)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.dast.correlator import correlate_dast_sast
from app.db import Base
from app.models import Asset, Cluster, DastScan, Finding, Scan


@pytest.fixture()
def db() -> Session:
    from app import models  # noqa: F401

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(
        bind=engine, autoflush=False, autocommit=False, future=True
    )
    s = SessionMaker()
    try:
        yield s
    finally:
        s.close()


def _asset(db: Session) -> Asset:
    a = Asset(
        repo_url=f"https://x/{uuid.uuid4()}",
        name="svc", criticality_source="unknown",
    )
    db.add(a); db.commit(); db.refresh(a)
    return a


def _scan(db: Session, asset_id) -> Scan:
    s = Scan(
        asset_id=asset_id, status="done",
        started_at=datetime.now(timezone.utc),
    )
    db.add(s); db.commit(); db.refresh(s)
    return s


def _dast_scan(db: Session, asset_id) -> DastScan:
    s = DastScan(
        asset_id=asset_id, target_url="https://alvo", profile="baseline",
        status="running",
    )
    db.add(s); db.commit(); db.refresh(s)
    return s


def _sast(db: Session, asset_id, scan_id, cwe: list[str], **over) -> Finding:
    base = dict(
        asset_id=asset_id, scan_id=scan_id,
        source_tool="semgrep", category="sast",
        rule_id="r", title="finding sast",
        fingerprint=uuid.uuid4().hex, status="open",
        cwe=cwe,
    )
    base.update(over)
    f = Finding(**base)
    db.add(f); db.commit(); db.refresh(f)
    return f


def _dast(
    db: Session, asset_id, scan_id, dast_scan_id, cwe: list[str], **over
) -> Finding:
    base = dict(
        asset_id=asset_id, scan_id=scan_id, dast_scan_id=dast_scan_id,
        source_tool="zap", category="dast",
        rule_id="40018", title="finding dast",
        fingerprint=uuid.uuid4().hex, status="open",
        cwe=cwe, url="https://alvo/x", http_method="GET",
    )
    base.update(over)
    f = Finding(**base)
    db.add(f); db.commit(); db.refresh(f)
    return f


# ---------------------------------------------------------------------------
# Casos basicos
# ---------------------------------------------------------------------------


def test_no_dast_findings_returns_empty_stats(db):
    a = _asset(db)
    ds = _dast_scan(db, a.id)
    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.cwes_examined == 0
    assert stats.clusters_created == 0


def test_dast_without_cwe_is_ignored(db):
    a = _asset(db)
    s = _scan(db, a.id)
    ds = _dast_scan(db, a.id)
    _dast(db, a.id, s.id, ds.id, cwe=[])
    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.cwes_examined == 0


def test_dast_with_uncorrelatable_cwe_is_ignored(db):
    """CWE que nao esta na lista de alto sinal nao gera correlacao."""
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    _dast(db, a.id, s.id, ds.id, cwe=["CWE-693"])  # CSP missing — nao corelatavel
    _sast(db, a.id, s.id, cwe=["CWE-693"])
    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.cwes_examined == 0


def test_dast_without_sast_match_does_not_cluster(db):
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])  # SQLi sem SAST par
    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.cwes_examined == 1
    assert stats.clusters_created == 0
    db.refresh(df)
    assert df.cluster_id is None


# ---------------------------------------------------------------------------
# Match basico CWE
# ---------------------------------------------------------------------------


def test_creates_new_cluster_with_dast_and_sast_matched(db):
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    sf = _sast(db, a.id, s.id, cwe=["CWE-89"], rule_id="python.sqli")
    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])

    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.clusters_created == 1
    assert stats.dast_findings_linked == 1
    assert stats.sast_findings_linked == 1

    db.refresh(sf); db.refresh(df)
    assert sf.cluster_id is not None
    assert sf.cluster_id == df.cluster_id

    cluster = db.get(Cluster, sf.cluster_id)
    assert cluster is not None
    assert cluster.source == "correlator-cwe"
    assert "SQL" in cluster.root_cause


def test_cwe_match_is_case_insensitive(db):
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    sf = _sast(db, a.id, s.id, cwe=["cwe-89"])
    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])
    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.clusters_created == 1
    db.refresh(sf); db.refresh(df)
    assert sf.cluster_id == df.cluster_id


def test_only_open_sast_findings_matter(db):
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    _sast(db, a.id, s.id, cwe=["CWE-89"], status="false_positive")
    _sast(db, a.id, s.id, cwe=["CWE-89"], status="fixed")
    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])
    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.clusters_created == 0
    db.refresh(df)
    assert df.cluster_id is None


def test_dast_findings_in_other_assets_are_ignored(db):
    a1 = _asset(db); a2 = _asset(db)
    s1 = _scan(db, a1.id); s2 = _scan(db, a2.id)
    ds1 = _dast_scan(db, a1.id)
    _sast(db, a2.id, s2.id, cwe=["CWE-89"])  # SAST no asset ERRADO
    df = _dast(db, a1.id, s1.id, ds1.id, cwe=["CWE-89"])

    stats = correlate_dast_sast(db, a1.id, ds1.id)
    assert stats.clusters_created == 0
    db.refresh(df)
    assert df.cluster_id is None


# ---------------------------------------------------------------------------
# Reuso de cluster existente
# ---------------------------------------------------------------------------


def test_reuses_existing_cluster_when_sast_already_clustered(db):
    """DAST novo deve entrar em cluster que ja agrupa os SAST matched."""
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    # Dois SAST ja agrupados num cluster pre-existente ("ai")
    c = Cluster(asset_id=a.id, root_cause="sqli pre-existente", confidence=0.9, source="ai")
    db.add(c); db.commit(); db.refresh(c)
    sf1 = _sast(db, a.id, s.id, cwe=["CWE-89"])
    sf2 = _sast(db, a.id, s.id, cwe=["CWE-89"])
    sf1.cluster_id = c.id; sf2.cluster_id = c.id
    db.commit()

    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])
    stats = correlate_dast_sast(db, a.id, ds.id)

    assert stats.clusters_reused == 1
    assert stats.clusters_created == 0
    db.refresh(df)
    assert df.cluster_id == c.id
    # Cluster original nao foi criado novo — confirmado pela source="ai".
    assert db.get(Cluster, df.cluster_id).source == "ai"


def test_does_not_merge_divergent_clusters(db):
    """Se SAST matched estao em clusters DIFERENTES, cria novo so para
    o DAST + eventuais SAST ainda sem cluster — nao fundir clusters."""
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    c1 = Cluster(asset_id=a.id, root_cause="r1", confidence=0.9, source="ai")
    c2 = Cluster(asset_id=a.id, root_cause="r2", confidence=0.9, source="ai")
    db.add_all([c1, c2]); db.commit(); db.refresh(c1); db.refresh(c2)

    sf1 = _sast(db, a.id, s.id, cwe=["CWE-89"]); sf1.cluster_id = c1.id
    sf2 = _sast(db, a.id, s.id, cwe=["CWE-89"]); sf2.cluster_id = c2.id
    sf3 = _sast(db, a.id, s.id, cwe=["CWE-89"])  # sem cluster
    db.commit()

    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])
    stats = correlate_dast_sast(db, a.id, ds.id)

    assert stats.clusters_created == 1
    assert stats.clusters_reused == 0
    db.refresh(sf1); db.refresh(sf2); db.refresh(sf3); db.refresh(df)
    # c1 e c2 preservados
    assert sf1.cluster_id == c1.id
    assert sf2.cluster_id == c2.id
    # Novo cluster recebeu sf3 (sem cluster) + df
    assert sf3.cluster_id is not None
    assert sf3.cluster_id not in (c1.id, c2.id)
    assert df.cluster_id == sf3.cluster_id


def test_dast_already_clustered_is_left_alone(db):
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    c = Cluster(asset_id=a.id, root_cause="pre", confidence=0.5, source="ai")
    db.add(c); db.commit(); db.refresh(c)
    # DAST ja em cluster — fetch nao retorna, nao reclusteriza
    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])
    df.cluster_id = c.id
    db.commit()
    _sast(db, a.id, s.id, cwe=["CWE-89"])  # SAST par exists

    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.clusters_created == 0
    db.refresh(df)
    assert df.cluster_id == c.id  # inalterado


# ---------------------------------------------------------------------------
# CWEs multiplos / multi-finding
# ---------------------------------------------------------------------------


def test_multiple_cwes_create_separate_clusters(db):
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    _sast(db, a.id, s.id, cwe=["CWE-89"])
    _sast(db, a.id, s.id, cwe=["CWE-79"])
    _dast(db, a.id, s.id, ds.id, cwe=["CWE-89"])
    _dast(db, a.id, s.id, ds.id, cwe=["CWE-79"])

    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.cwes_examined == 2
    assert stats.clusters_created == 2
    assert stats.dast_findings_linked == 2
    assert stats.sast_findings_linked == 2


def test_single_dast_with_multiple_cwes_can_appear_in_two_matches(db):
    """DAST com [CWE-78, CWE-89]: se os dois tem SAST par, cada cluster o puxa.
    Mas finding so pode ter 1 cluster_id — o primeiro CWE processado vence.
    Teste garante que nao explode e que o DAST acaba em um dos clusters."""
    a = _asset(db); s = _scan(db, a.id); ds = _dast_scan(db, a.id)
    _sast(db, a.id, s.id, cwe=["CWE-89"])
    _sast(db, a.id, s.id, cwe=["CWE-78"])
    df = _dast(db, a.id, s.id, ds.id, cwe=["CWE-89", "CWE-78"])

    stats = correlate_dast_sast(db, a.id, ds.id)
    assert stats.cwes_examined == 2
    # Pelo menos 1 cluster criado; DAST acabou em exatamente 1
    assert stats.clusters_created >= 1
    db.refresh(df)
    assert df.cluster_id is not None
