"""Testes do remediator — Sonnet + arquivo alvo, com IA mockada."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import AIAnalysis, Asset, Finding, Remediation, Scan
from app.schemas.ai import RemediationOutput


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


def _make_asset(db: Session, **over) -> Asset:
    a = Asset(
        repo_url=f"https://x/{uuid.uuid4()}",
        name="svc",
        criticality=4,
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
        title="SQLi via f-string",
        description="query montada com f-string",
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


def test_remediation_skips_when_ai_disabled(db, tmp_path: Path):
    from app.core.remediator import run_remediation_for_finding

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    src = tmp_path / "x.py"
    src.write_text("print(1)")
    f = _make_finding(db, a.id, s.id, file_path="x.py")

    class _StubAI:
        enabled = False

    with patch("app.core.remediator.get_ai", return_value=_StubAI()):
        row = run_remediation_for_finding(db, a, f, tmp_path)
    assert row is None
    assert db.query(Remediation).count() == 0


def test_remediation_returns_none_when_file_missing(db, tmp_path: Path):
    from app.core.remediator import run_remediation_for_finding

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    f = _make_finding(db, a.id, s.id, file_path="nope.py")

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            raise AssertionError("nao deveria chamar")

    with patch("app.core.remediator.get_ai", return_value=_StubAI()):
        row = run_remediation_for_finding(db, a, f, tmp_path)
    assert row is None


def test_remediation_persists_diff_and_includes_prior_rationale(db, tmp_path: Path):
    from app.core.remediator import run_remediation_for_finding

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    (tmp_path / "app").mkdir()
    src = tmp_path / "app" / "a.py"
    src.write_text("def get(id):\n    return db.execute(f'SELECT * FROM t WHERE id={id}')\n")
    f = _make_finding(db, a.id, s.id, file_path="app/a.py")

    # analise anterior existe -> deve aparecer no prompt
    db.add(AIAnalysis(
        finding_id=f.id,
        reachability="reachable",
        exploitability=5, business_impact=4,
        risk_score=80, is_likely_false_positive=False,
        confidence=0.9,
        rationale="rota get chama execute com f-string sem parametros",
        model="sonnet", prompt_version="v1",
    ))
    db.commit()

    response = RemediationOutput(
        patch_diff="--- a/app/a.py\n+++ b/app/a.py\n@@ -1,2 +1,2 @@\n-def get(id):\n-    return db.execute(f'SELECT * FROM t WHERE id={id}')\n+def get(id):\n+    return db.execute('SELECT * FROM t WHERE id=?', (id,))\n",
        explanation="parametrizar a query em execute",
        breaking_risk="low",
        test_suggestion="testar get com id malicioso",
    )
    captured = {}

    class _StubAI:
        enabled = True
        def call_structured(self, **kw):
            captured.update(kw.get("prompt_vars", {}))
            return response, {
                "input_tokens": 500, "output_tokens": 200,
                "model": "claude-sonnet-4-6", "prompt_version": "v1",
            }

    with patch("app.core.remediator.get_ai", return_value=_StubAI()):
        row = run_remediation_for_finding(db, a, f, tmp_path)

    assert row is not None
    assert row.breaking_risk == "low"
    assert row.applied is False
    assert row.model == "claude-sonnet-4-6"
    assert "SELECT" in row.patch_diff
    # arquivo alvo entrou no prompt
    assert "SELECT" in captured["file_content"]
    # rationale anterior entrou
    assert "f-string" in captured["prior_rationale"]


def test_remediation_ai_unavailable_returns_none(db, tmp_path: Path):
    from app.ai.client import AIUnavailableError
    from app.core.remediator import run_remediation_for_finding

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    src = tmp_path / "x.py"
    src.write_text("print(1)")
    f = _make_finding(db, a.id, s.id, file_path="x.py")

    class _StubAI:
        enabled = True
        def call_structured(self, **_kw):
            raise AIUnavailableError("boom")

    with patch("app.core.remediator.get_ai", return_value=_StubAI()):
        row = run_remediation_for_finding(db, a, f, tmp_path)
    assert row is None
    assert db.query(Remediation).count() == 0


def test_remediation_no_prior_rationale_uses_dash(db, tmp_path: Path):
    from app.core.remediator import run_remediation_for_finding

    a = _make_asset(db)
    s = _make_scan(db, a.id)
    src = tmp_path / "x.py"
    src.write_text("print(1)")
    f = _make_finding(db, a.id, s.id, file_path="x.py")

    captured = {}
    response = RemediationOutput(
        patch_diff="", explanation="sem fix disponivel",
        breaking_risk="low", test_suggestion="n/a",
    )

    class _StubAI:
        enabled = True
        def call_structured(self, **kw):
            captured.update(kw.get("prompt_vars", {}))
            return response, {"model": "sonnet", "prompt_version": "v1", "input_tokens": 0, "output_tokens": 0}

    with patch("app.core.remediator.get_ai", return_value=_StubAI()):
        row = run_remediation_for_finding(db, a, f, tmp_path)
    assert row is not None
    assert row.patch_diff is None  # string vazia normalizada
    assert captured["prior_rationale"] == "-"
