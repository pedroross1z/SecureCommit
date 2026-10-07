"""Roteamento de prompts por categoria: DAST → dast_*, demais → genericos.

Stub o AIClient para capturar o `prompt_name` e os `prompt_vars` enviados.
Nao faz chamada real a Anthropic.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import Asset, Finding, Scan
from app.schemas.ai import DeepAnalysisResult, RemediationOutput, TriageBatch, TriageResult


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
        name="svc", criticality=4, criticality_source="ai",
        internet_facing=True, handles_pii=True, has_auth=True,
        languages={"python": 1.0},
    )
    db.add(a); db.commit(); db.refresh(a)
    return a


def _scan(db: Session, asset_id) -> Scan:
    s = Scan(asset_id=asset_id, status="running", started_at=datetime.now(timezone.utc))
    db.add(s); db.commit(); db.refresh(s)
    return s


def _finding(db: Session, asset_id, scan_id, **over) -> Finding:
    base = dict(
        asset_id=asset_id, scan_id=scan_id,
        source_tool="semgrep", category="sast",
        rule_id="rule", title="t",
        severity_raw="high", file_path="app/a.py",
        line_start=1, line_end=2,
        fingerprint=uuid.uuid4().hex, status="open",
    )
    base.update(over)
    f = Finding(**base)
    db.add(f); db.commit(); db.refresh(f)
    return f


class _CapturingAI:
    """Stub AIClient que registra chamadas e devolve respostas canonicas."""

    enabled = True

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def call_structured(
        self, *, prompt_name, prompt_vars, response_model, model, **_kw
    ):
        self.calls.append({
            "prompt_name": prompt_name,
            "prompt_vars": dict(prompt_vars),
            "model": model,
        })
        if response_model is TriageBatch:
            # Devolve 1 TriageResult para cada finding_id presente no payload.
            import json as _json
            payload = _json.loads(prompt_vars["findings_json"])
            results = [
                TriageResult(
                    finding_id=item["id"],
                    reachability="reachable",
                    exploitability=3,
                    business_impact=3,
                    is_likely_false_positive=False,
                    confidence=0.7,
                    rationale="stub",
                )
                for item in payload
            ]
            parsed = TriageBatch(results=results)
        elif response_model is DeepAnalysisResult:
            parsed = DeepAnalysisResult(
                reachability="reachable",
                exploitability=3,
                business_impact=4,
                is_likely_false_positive=False,
                confidence=0.9,
                rationale="stub deep",
            )
        elif response_model is RemediationOutput:
            parsed = RemediationOutput(
                patch_diff="",
                explanation="stub remediation",
                breaking_risk="low",
                test_suggestion="rerun scan",
            )
        else:
            raise AssertionError(f"response_model inesperado: {response_model}")

        return parsed, {
            "model": model, "prompt_version": "v1",
            "input_tokens": 1, "output_tokens": 1, "cached": False,
        }


# ---------------------------------------------------------------------------
# Triage routing
# ---------------------------------------------------------------------------


def test_triage_routes_code_to_triage_and_dast_to_dast_triage(db):
    from app.core.prioritizer import run_triage_scan

    a = _asset(db); s = _scan(db, a.id)
    # 2 SAST + 1 DAST no mesmo scan
    _finding(db, a.id, s.id, category="sast", rule_id="r1")
    _finding(db, a.id, s.id, category="sca", rule_id="r2", source_tool="trivy")
    _finding(
        db, a.id, s.id, category="dast", source_tool="zap",
        rule_id="40018", url="https://alvo/x", http_method="GET",
        parameter="q", cwe=["CWE-89"], evidence="SQL error",
    )

    stub = _CapturingAI()
    with patch("app.core.prioritizer.get_ai", return_value=stub):
        stats = run_triage_scan(db, a.id, s.id)

    # 2 batches no total: 1 pra codigo (2 findings), 1 pra DAST (1 finding)
    assert stats.batches == 2
    prompt_names = [c["prompt_name"] for c in stub.calls]
    assert prompt_names.count("triage") == 1
    assert prompt_names.count("dast_triage") == 1
    assert stats.analyses_created == 3


def test_triage_only_dast_findings_uses_dast_prompt_only(db):
    from app.core.prioritizer import run_triage_scan

    a = _asset(db); s = _scan(db, a.id)
    _finding(
        db, a.id, s.id, category="dast", source_tool="zap",
        rule_id="40018", url="https://alvo/x", http_method="POST",
        parameter="username", cwe=["CWE-89"], evidence="SQL error",
    )

    stub = _CapturingAI()
    with patch("app.core.prioritizer.get_ai", return_value=stub):
        run_triage_scan(db, a.id, s.id)

    assert [c["prompt_name"] for c in stub.calls] == ["dast_triage"]


def test_triage_only_code_findings_does_not_call_dast_prompt(db):
    from app.core.prioritizer import run_triage_scan

    a = _asset(db); s = _scan(db, a.id)
    _finding(db, a.id, s.id, category="sast", rule_id="r1")

    stub = _CapturingAI()
    with patch("app.core.prioritizer.get_ai", return_value=stub):
        run_triage_scan(db, a.id, s.id)

    assert [c["prompt_name"] for c in stub.calls] == ["triage"]


def test_dast_triage_payload_contains_http_fields(db):
    from app.core.prioritizer import run_triage_scan

    a = _asset(db); s = _scan(db, a.id)
    _finding(
        db, a.id, s.id, category="dast", source_tool="zap",
        rule_id="40018", url="https://alvo/login", http_method="POST",
        parameter="user", cwe=["CWE-89"], evidence="PostgreSQL error",
        solution="Use prepared stmts",
    )

    stub = _CapturingAI()
    with patch("app.core.prioritizer.get_ai", return_value=stub):
        run_triage_scan(db, a.id, s.id)

    import json as _json
    call = next(c for c in stub.calls if c["prompt_name"] == "dast_triage")
    payload = _json.loads(call["prompt_vars"]["findings_json"])
    assert payload[0]["url"] == "https://alvo/login"
    assert payload[0]["http_method"] == "POST"
    assert payload[0]["parameter"] == "user"
    assert payload[0]["cwe"] == ["CWE-89"]
    assert "SQL" in payload[0]["evidence"] or "PostgreSQL" in payload[0]["evidence"]


# ---------------------------------------------------------------------------
# Deep analysis routing
# ---------------------------------------------------------------------------


def test_deep_analysis_dast_uses_dast_prompt_and_no_file(db, tmp_path):
    from app.core.prioritizer import run_deep_analysis_for_finding

    a = _asset(db); s = _scan(db, a.id)
    f = _finding(
        db, a.id, s.id, category="dast", source_tool="zap",
        rule_id="40018", file_path=None,
        url="https://alvo/x", http_method="GET",
        parameter="q", cwe=["CWE-89"], evidence="err",
    )

    stub = _CapturingAI()
    # repo_path nao existe no disco — deep analysis DAST nao deve nem olhar
    with patch("app.core.prioritizer.get_ai", return_value=stub):
        row = run_deep_analysis_for_finding(db, a, f, Path("/nonexistent"))

    assert row is not None
    assert [c["prompt_name"] for c in stub.calls] == ["dast_deep_analysis"]
    vars_sent = stub.calls[0]["prompt_vars"]
    assert vars_sent["url"] == "https://alvo/x"
    assert vars_sent["http_method"] == "GET"
    # Garantia: NAO ha file_content/file_lines no prompt DAST
    assert "file_content" not in vars_sent
    assert "file_lines" not in vars_sent


def test_deep_analysis_sast_uses_generic_prompt(db, tmp_path):
    from app.core.prioritizer import run_deep_analysis_for_finding

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text("print('hi')\n", encoding="utf-8")

    a = _asset(db); s = _scan(db, a.id)
    f = _finding(db, a.id, s.id, category="sast", file_path="app/a.py")

    stub = _CapturingAI()
    with patch("app.core.prioritizer.get_ai", return_value=stub):
        row = run_deep_analysis_for_finding(db, a, f, tmp_path)

    assert row is not None
    assert [c["prompt_name"] for c in stub.calls] == ["deep_analysis"]


# ---------------------------------------------------------------------------
# Remediation routing
# ---------------------------------------------------------------------------


def test_remediation_dast_uses_dast_prompt_without_file(db):
    from app.core.remediator import run_remediation_for_finding

    a = _asset(db); s = _scan(db, a.id)
    f = _finding(
        db, a.id, s.id, category="dast", source_tool="zap",
        rule_id="40018", file_path=None,
        url="https://alvo/x", http_method="GET",
        parameter="q", cwe=["CWE-89"],
        evidence="SQL error",
        solution="Use prepared stmts",
    )

    stub = _CapturingAI()
    with patch("app.core.remediator.get_ai", return_value=stub):
        row = run_remediation_for_finding(db, a, f, Path("/nonexistent"))

    assert row is not None  # DAST nao precisa de arquivo
    assert [c["prompt_name"] for c in stub.calls] == ["dast_remediation"]
    vars_sent = stub.calls[0]["prompt_vars"]
    assert vars_sent["url"] == "https://alvo/x"
    assert vars_sent["parameter"] == "q"
    # Prompt DAST nao exige file_content
    assert "file_content" not in vars_sent


def test_remediation_sast_uses_generic_prompt(db, tmp_path):
    from app.core.remediator import run_remediation_for_finding

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text("print('hi')\n", encoding="utf-8")

    a = _asset(db); s = _scan(db, a.id)
    f = _finding(db, a.id, s.id, category="sast", file_path="app/a.py")

    stub = _CapturingAI()
    with patch("app.core.remediator.get_ai", return_value=stub):
        row = run_remediation_for_finding(db, a, f, tmp_path)

    assert row is not None
    assert [c["prompt_name"] for c in stub.calls] == ["remediation"]


# ---------------------------------------------------------------------------
# Validacao de arquivo de prompt
# ---------------------------------------------------------------------------


def test_dast_prompt_files_exist_and_have_version():
    from app.ai.client import load_prompt

    for name in ("dast_triage", "dast_deep_analysis", "dast_remediation"):
        template, version = load_prompt(name)
        assert version != "v0", f"{name}.md sem bloco <!-- version: ... -->"
        assert "<<" in template, f"{name}.md sem variaveis <<VAR>>"
