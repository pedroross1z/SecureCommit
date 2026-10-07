"""Testes do policy engine (Fase 6)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.policy import (
    Policy,
    Rule,
    RuleCondition,
    evaluate_policy,
    list_policies,
    load_policy,
)
from app.db import Base
from app.models import AIAnalysis, Asset, Finding, Scan


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


def _asset(db: Session) -> Asset:
    a = Asset(repo_url=f"https://x/{uuid.uuid4()}", name="svc", criticality_source="unknown")
    db.add(a); db.commit(); db.refresh(a)
    return a


def _scan(db: Session, asset_id, minutes_ago: int = 0, status: str = "done") -> Scan:
    now = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    s = Scan(asset_id=asset_id, status=status, started_at=now, finished_at=now)
    db.add(s); db.commit(); db.refresh(s)
    return s


def _finding(db: Session, asset_id, scan_id, **over) -> Finding:
    base = dict(
        asset_id=asset_id, scan_id=scan_id,
        source_tool="semgrep", category="sast",
        rule_id="python.sqli", title="finding",
        severity_raw="medium",
        fingerprint=uuid.uuid4().hex, status="open",
    )
    base.update(over)
    f = Finding(**base)
    db.add(f); db.commit(); db.refresh(f)
    return f


def _ai(db: Session, finding_id, score: int) -> None:
    db.add(AIAnalysis(
        finding_id=finding_id, rationale="r", model="m", prompt_version="v1",
        risk_score=score,
    ))
    db.commit()


# ---------------- loader ----------------

def test_loader_reads_yaml(tmp_path: Path, monkeypatch):
    (tmp_path / "p1.yaml").write_text(
        "name: p1\nrules:\n  - id: r1\n    action: fail\n    when:\n      category_in: [secret]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("app.core.policy.settings.policies_dir", str(tmp_path))
    p = load_policy("p1")
    assert p.name == "p1"
    assert p.rules[0].id == "r1"
    assert p.rules[0].when.category_in == ["secret"]


def test_loader_normalizes_name_to_filename(tmp_path: Path, monkeypatch):
    (tmp_path / "canonical.yaml").write_text("name: outro\nrules: []\n", encoding="utf-8")
    monkeypatch.setattr("app.core.policy.settings.policies_dir", str(tmp_path))
    p = load_policy("canonical")
    assert p.name == "canonical"


def test_loader_missing_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("app.core.policy.settings.policies_dir", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        load_policy("nope")


def test_loader_invalid_raises(tmp_path: Path, monkeypatch):
    (tmp_path / "bad.yaml").write_text(
        "name: bad\nrules:\n  - action: fail\n",  # falta 'id'
        encoding="utf-8",
    )
    monkeypatch.setattr("app.core.policy.settings.policies_dir", str(tmp_path))
    with pytest.raises(ValueError):
        load_policy("bad")


def test_list_policies_skips_bad(tmp_path: Path, monkeypatch):
    (tmp_path / "ok.yaml").write_text("name: ok\nrules: []\n", encoding="utf-8")
    (tmp_path / "bad.yaml").write_text("name: bad\nrules:\n  - action: fail\n", encoding="utf-8")
    monkeypatch.setattr("app.core.policy.settings.policies_dir", str(tmp_path))
    names = [p.name for p in list_policies()]
    assert names == ["ok"]


# ---------------- evaluate ----------------

def _p(*rules: Rule) -> Policy:
    return Policy(name="t", rules=list(rules))


def test_empty_asset_passes(db):
    a = _asset(db)
    res = evaluate_policy(db, a.id, _p(Rule(id="any", when=RuleCondition())))
    assert res.passed is True
    assert res.findings_considered == 0
    assert res.scan_id is None


def test_uses_latest_done_scan(db):
    a = _asset(db)
    old = _scan(db, a.id, minutes_ago=60)
    new = _scan(db, a.id, minutes_ago=1)
    _scan(db, a.id, minutes_ago=0, status="running")  # ignorado
    _finding(db, a.id, old.id, category="secret")
    res = evaluate_policy(
        db, a.id, _p(Rule(id="s", when=RuleCondition(category_in=["secret"])))
    )
    assert res.scan_id == new.id
    assert res.findings_considered == 0
    assert res.passed is True


def test_category_and_severity_match(db):
    a = _asset(db); s = _scan(db, a.id)
    _finding(db, a.id, s.id, category="secret", severity_raw="high")
    _finding(db, a.id, s.id, category="sast", severity_raw="medium")
    res = evaluate_policy(
        db, a.id, _p(Rule(id="sec", when=RuleCondition(category_in=["secret"])))
    )
    assert res.fail_count == 1
    assert res.passed is False
    assert res.violations[0].rule_id == "sec"


def test_min_risk_score_ignores_unscored(db):
    a = _asset(db); s = _scan(db, a.id)
    f1 = _finding(db, a.id, s.id); _ai(db, f1.id, 90)
    _finding(db, a.id, s.id)  # sem score
    res = evaluate_policy(
        db, a.id, _p(Rule(id="hi", when=RuleCondition(min_risk_score=80)))
    )
    assert res.fail_count == 1
    assert res.violations[0].finding_id == f1.id


def test_cve_present_and_cwe_any(db):
    a = _asset(db); s = _scan(db, a.id)
    _finding(db, a.id, s.id, category="sca", cve="CVE-2024-1", severity_raw="high")
    _finding(db, a.id, s.id, category="sast", cwe=["CWE-89"])
    res = evaluate_policy(db, a.id, _p(
        Rule(id="cve", when=RuleCondition(cve_present=True, severity_in=["high", "critical"])),
        Rule(id="sqli", when=RuleCondition(cwe_any=["cwe-89"])),
    ))
    assert res.rule_hits == {"cve": 1, "sqli": 1}
    assert res.fail_count == 2


def test_warn_does_not_fail(db):
    a = _asset(db); s = _scan(db, a.id)
    _finding(db, a.id, s.id, severity_raw="high")
    res = evaluate_policy(
        db, a.id, _p(Rule(id="w", action="warn", when=RuleCondition(severity_in=["high"])))
    )
    assert res.passed is True
    assert res.warn_count == 1
    assert res.fail_count == 0


def test_exclude_status_default_skips_fp(db):
    a = _asset(db); s = _scan(db, a.id)
    _finding(db, a.id, s.id, category="secret", status="false_positive")
    _finding(db, a.id, s.id, category="secret", status="open")
    res = evaluate_policy(
        db, a.id, _p(Rule(id="s", when=RuleCondition(category_in=["secret"])))
    )
    assert res.fail_count == 1


def test_scan_id_override(db):
    a = _asset(db)
    s_old = _scan(db, a.id, minutes_ago=60)
    s_new = _scan(db, a.id, minutes_ago=1)
    _finding(db, a.id, s_old.id, category="secret")
    _finding(db, a.id, s_new.id, category="sast")
    res = evaluate_policy(
        db, a.id, _p(Rule(id="s", when=RuleCondition(category_in=["secret"]))),
        scan_id=s_old.id,
    )
    assert res.scan_id == s_old.id
    assert res.fail_count == 1
