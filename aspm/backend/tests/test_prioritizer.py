"""Testes do prioritizer — risk_score deterministico + fluxo com IA mockada."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import AIAnalysis, Asset, Finding, Scan
from app.schemas.ai import DeepAnalysisResult, TriageBatch, TriageResult


@pytest.fixture()
def db() -> Session:
    from app import models  # noqa: F401

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    s = SessionMaker()
    try:
        yield s
    finally:
        s.close()


def _make_asset(db: Session, criticality: int = 4, **over) -> Asset:
    a = Asset(
        repo_url=f"https://x/{uuid.uuid4()}",
        name="svc",
        criticality=criticality,
        criticality_source="ai",
        internet_facing=True,
        handles_pii=True,
        has_auth=True,
        languages={"python": 1.0},
        **over,
    )
    db.add(a); db.commit(); db.refresh(a)
    return a


def _make_scan(db: Session, asset_id) -> Scan:
    s = Scan(asset_id=asset_id, status="running", started_at=datetime.now(timezone.utc))
    db.add(s); db.commit(); db.refresh(s)
    return s


def _make_finding(db: Session, asset_id, scan_id, **over) -> Finding:
    base = dict(
        asset_id=asset_id,
        scan_id=scan_id,
        source_tool="semgrep",
        category="sast",
        rule_id="python.sqli",
        title="SQLi",
        severity_raw="high",
        file_path="app/a.py",
        line_start=10,
        line_end=12,
        fingerprint=uuid.uuid4().hex,
        status="open",
    )
    base.update(over)
    f = Finding(**base)
    db.add(f); db.commit(); db.refresh(f)
    return f


# ---------- compute_risk_score ----------


def test_risk_score_reachable_critical_maxes_high():
    from app.core.prioritizer import compute_risk_score

    s = compute_risk_score(
        severity_raw="critical", reachability="reachable",
        exploitability=5, business_impact=5, is_likely_false_positive=False,
        asset_criticality=5,
    )
    # 90 * 1.0 * 1.0 = 90
    assert s == 90


def test_risk_score_unreachable_reduces():
    from app.core.prioritizer import compute_risk_score

    reachable = compute_risk_score(
        severity_raw="high", reachability="reachable",
        exploitability=3, business_impact=3, is_likely_false_positive=False,
        asset_criticality=3,
    )
    unreachable = compute_risk_score(
        severity_raw="high", reachability="unreachable",
        exploitability=3, business_impact=3, is_likely_false_positive=False,
        asset_criticality=3,
    )
    assert unreachable < reachable
    # reachable: 70 * 0.6 * 1.0 = 42; unreachable: 70 * 0.6 * 0.3 = 12.6 -> 13
    assert reachable == 42
    assert unreachable == 13


def test_risk_score_false_positive_penalty():
    from app.core.prioritizer import compute_risk_score

    s = compute_risk_score(
        severity_raw="critical", reachability="reachable",
        exploitability=5, business_impact=5, is_likely_false_positive=True,
        asset_criticality=5,
    )
    # 90 * 1.0 * 1.0 * 0.3 = 27
    assert s == 27


def test_risk_score_defaults_when_missing_fields():
    from app.core.prioritizer import compute_risk_score

    s = compute_risk_score(
        severity_raw=None, reachability=None,
        exploitability=None, business_impact=None, is_likely_false_positive=None,
        asset_criticality=None,
    )
    # base 30 (unknown) * factor 0.6 (3+3+3=9/15) * 0.8 (unknown reach) = 14.4 -> 14
    assert s == 14


def test_risk_score_clamped_to_100():
    from app.core.prioritizer import compute_risk_score

    s = compute_risk_score(
        severity_raw="critical", reachability="reachable",
        exploitability=5, business_impact=5, is_likely_false_positive=False,
        asset_criticality=5,
    )
    assert 0 <= s <= 100


# ---------- should_deep_analyze ----------


def test_should_deep_high_risk_not_fp():
    from app.core.prioritizer import should_deep_analyze

    assert should_deep_analyze(
        risk_score=70, confidence=0.9,
        is_likely_false_positive=False, reachability="reachable",
    ) is True


def test_should_deep_skip_confirmed_fp():
    from app.core.prioritizer import should_deep_analyze

    assert should_deep_analyze(
        risk_score=80, confidence=0.9,
        is_likely_false_positive=True, reachability="reachable",
    ) is False


def test_should_deep_skip_confirmed_unreachable():
    from app.core.prioritizer import should_deep_analyze

    assert should_deep_analyze(
        risk_score=80, confidence=0.9,
        is_likely_false_positive=False, reachability="unreachable",
    ) is False


def test_should_deep_low_confidence_escalates():
    from app.core.prioritizer import should_deep_analyze

    assert should_deep_analyze(
        risk_score=30, confidence=0.3,
        is_likely_false_positive=False, reachability="unknown",
    ) is True


def test_should_deep_low_risk_high_confidence_skips():
    from app.core.prioritizer import should_deep_analyze

    assert should_deep_analyze(
        risk_score=20, confidence=0.9,
        is_likely_false_positive=False, reachability="reachable",
    ) is False


# ---------- run_triage_scan ----------


def test_triage_skips_when_ai_disabled(db):
    from app.core.prioritizer import run_triage_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    _make_finding(db, a.id, s.id)

    class _StubAI:
        enabled = False

    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        stats = run_triage_scan(db, a.id, s.id)
    assert stats.analyses_created == 0
    assert stats.batches == 0


def test_triage_persists_analysis_and_score(db):
    from app.core.prioritizer import run_triage_scan

    a = _make_asset(db, criticality=5)
    s = _make_scan(db, a.id)
    f = _make_finding(db, a.id, s.id, severity_raw="critical")

    response = TriageBatch(
        results=[
            TriageResult(
                finding_id=str(f.id),
                reachability="reachable",
                exploitability=5, business_impact=5,
                is_likely_false_positive=False,
                confidence=0.9, rationale="input em rota HTTP",
            )
        ]
    )

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            return response, {
                "input_tokens": 200, "output_tokens": 80,
                "model": "claude-haiku-4-5", "prompt_version": "v1",
            }

    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        stats = run_triage_scan(db, a.id, s.id)

    assert stats.analyses_created == 1
    assert stats.ai_calls_ok == 1
    row = db.query(AIAnalysis).filter_by(finding_id=f.id).one()
    assert row.risk_score == 90
    assert row.reachability == "reachable"
    assert row.model == "claude-haiku-4-5"


def test_triage_ignores_hallucinated_ids(db):
    from app.core.prioritizer import run_triage_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    _make_finding(db, a.id, s.id)

    response = TriageBatch(
        results=[
            TriageResult(
                finding_id=str(uuid.uuid4()),  # id inexistente
                reachability="reachable",
                exploitability=3, business_impact=3,
                is_likely_false_positive=False,
                confidence=0.5, rationale="x",
            )
        ]
    )

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            return response, {"input_tokens": 0, "output_tokens": 0}

    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        stats = run_triage_scan(db, a.id, s.id)
    assert stats.analyses_created == 0


def test_triage_batches_over_size(db):
    from app.core.prioritizer import _TRIAGE_BATCH_SIZE, run_triage_scan

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    for i in range(_TRIAGE_BATCH_SIZE + 3):
        _make_finding(db, a.id, s.id, fingerprint=f"fp{i}", file_path=f"f{i}.py")

    calls = {"n": 0}

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            calls["n"] += 1
            return TriageBatch(results=[]), {"input_tokens": 0, "output_tokens": 0}

    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        stats = run_triage_scan(db, a.id, s.id)
    assert calls["n"] == 2
    assert stats.batches == 2


# ---------- deep analysis ----------


def test_deep_analysis_reads_file_and_persists(db, tmp_path: Path):
    from app.core.prioritizer import run_deep_analysis_for_finding

    a = _make_asset(db, criticality=5)
    s = _make_scan(db, a.id)
    (tmp_path / "app").mkdir()
    src = tmp_path / "app" / "a.py"
    src.write_text("def get(id):\n    return db.execute(f'SELECT * FROM t WHERE id={id}')\n")
    f = _make_finding(db, a.id, s.id, file_path="app/a.py", severity_raw="critical")

    response = DeepAnalysisResult(
        reachability="reachable",
        exploitability=5, business_impact=4,
        is_likely_false_positive=False,
        confidence=0.95,
        rationale="rota get chama execute com f-string sem parametros",
    )

    captured = {}

    class _StubAI:
        enabled = True
        def call_structured(self, **kw):
            captured.update(kw.get("prompt_vars", {}))
            return response, {
                "input_tokens": 800, "output_tokens": 120,
                "model": "claude-sonnet-4-6", "prompt_version": "v1",
            }

    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        row = run_deep_analysis_for_finding(db, a, f, tmp_path)

    assert row is not None
    assert row.model == "claude-sonnet-4-6"
    assert row.reachability == "reachable"
    # 90 * (5+4+5)/15=0.933 * 1.0 = 84.0 -> 84
    assert row.risk_score == 84
    # o prompt recebeu o conteudo do arquivo
    assert "SELECT" in captured["file_content"]


def test_deep_analysis_returns_none_when_file_missing(db, tmp_path: Path):
    from app.core.prioritizer import run_deep_analysis_for_finding

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    f = _make_finding(db, a.id, s.id, file_path="does/not/exist.py")

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            raise AssertionError("nao deveria chamar")

    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        row = run_deep_analysis_for_finding(db, a, f, tmp_path)
    assert row is None


def test_deep_analysis_returns_none_when_ai_disabled(db, tmp_path: Path):
    from app.core.prioritizer import run_deep_analysis_for_finding

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    src = tmp_path / "x.py"
    src.write_text("print(1)")
    f = _make_finding(db, a.id, s.id, file_path="x.py")

    class _StubAI:
        enabled = False

    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        row = run_deep_analysis_for_finding(db, a, f, tmp_path)
    assert row is None


def test_deep_dives_respects_top_k_and_ordering(db, tmp_path: Path):
    from app.core.prioritizer import TriageStats, run_deep_dives_for_scan

    a = _make_asset(db, criticality=5)
    s = _make_scan(db, a.id)

    # cria 4 findings + AIAnalysis com risk_scores diferentes
    scores = [30, 90, 70, 50]
    findings = []
    for i, score in enumerate(scores):
        src = tmp_path / f"f{i}.py"
        src.write_text("print(1)")
        f = _make_finding(db, a.id, s.id, file_path=f"f{i}.py", fingerprint=f"fp{i}")
        db.add(AIAnalysis(
            finding_id=f.id,
            reachability="reachable",
            exploitability=3, business_impact=3,
            risk_score=score,
            is_likely_false_positive=False,
            confidence=0.9,
            rationale="x", model="haiku", prompt_version="v1",
        ))
        db.commit()
        findings.append(f)

    picked_files: list[str] = []

    class _StubAI:
        enabled = True
        def call_structured(self, **kw):
            picked_files.append(kw["prompt_vars"]["file_path"])
            return DeepAnalysisResult(
                reachability="reachable",
                exploitability=3, business_impact=3,
                is_likely_false_positive=False,
                confidence=0.95, rationale="x",
            ), {"input_tokens": 10, "output_tokens": 10, "model": "sonnet", "prompt_version": "v1"}

    stats = TriageStats()
    with patch("app.core.prioritizer.get_ai", return_value=_StubAI()):
        run_deep_dives_for_scan(db, a.id, s.id, tmp_path, stats, top_k=2)

    assert stats.deep_dives == 2
    assert stats.deep_ok == 2
    # top 2 por score: 90 (f1) e 70 (f2)
    assert picked_files == ["f1.py", "f2.py"]
