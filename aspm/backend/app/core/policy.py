"""Pilar 6 — Policy engine.

Policies sao arquivos YAML em `settings.policies_dir` (default: D:/ASPM/aspm/policies/).
Cada policy tem uma lista de rules com condicoes sobre findings; a avaliacao
percorre os findings 'open' do ultimo scan 'done' do asset e coleta violacoes.

Rules sao independentes: um finding pode violar varias, e um scan so passa se
nenhuma rule com action='fail' for violada.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal
from uuid import UUID

import yaml
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AIAnalysis, Finding, Scan

logger = logging.getLogger("aspm.policy")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

Action = Literal["fail", "warn"]


class RuleCondition(BaseModel):
    """Condicoes AND. Todas opcionais; rule sem nenhuma casa em todos os findings."""

    category_in: list[str] | None = None
    severity_in: list[str] | None = None
    min_risk_score: int | None = Field(default=None, ge=0, le=100)
    cwe_any: list[str] | None = None
    cve_present: bool | None = None
    package_name_in: list[str] | None = None
    rule_id_in: list[str] | None = None
    tool_in: list[str] | None = None
    # findings com status nestes valores sao ignorados por esta rule
    exclude_status: list[str] = Field(
        default_factory=lambda: ["false_positive", "accepted_risk", "fixed"]
    )


class Rule(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    description: str | None = None
    action: Action = "fail"
    when: RuleCondition = Field(default_factory=RuleCondition)


class Policy(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = None
    rules: list[Rule] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _policies_dir() -> Path:
    return Path(settings.policies_dir)


def load_policy(name: str) -> Policy:
    """Carrega policy por nome (sem extensao). Levanta FileNotFoundError/ValueError."""
    path = _policies_dir() / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"policy nao encontrada: {name} (procurado em {path})")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    try:
        policy = Policy.model_validate(data)
    except ValidationError as e:
        raise ValueError(f"policy '{name}' invalida: {e}") from e
    if policy.name != name:
        # aceita mas alinha: o nome do arquivo e canonico
        policy = policy.model_copy(update={"name": name})
    return policy


def list_policies() -> list[Policy]:
    d = _policies_dir()
    if not d.exists():
        return []
    out: list[Policy] = []
    for path in sorted(d.glob("*.yaml")):
        try:
            out.append(load_policy(path.stem))
        except Exception as e:
            logger.warning("policy %s ignorada: %s", path.name, e)
    return out


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


class Violation(BaseModel):
    rule_id: str
    action: Action
    finding_id: UUID
    finding_title: str
    file_path: str | None
    severity: str | None
    risk_score: int | None
    category: str
    tool: str


class PolicyEvaluation(BaseModel):
    policy_name: str
    asset_id: UUID
    scan_id: UUID | None
    passed: bool
    findings_considered: int
    fail_count: int
    warn_count: int
    violations: list[Violation]
    # {rule_id: n_matches} para debug/summary rapido
    rule_hits: dict[str, int]


def _severity_matches(f_sev: str | None, wanted: list[str]) -> bool:
    if not wanted:
        return True
    s = (f_sev or "unknown").lower()
    return s in {w.lower() for w in wanted}


def _cwe_matches(f_cwe: list[str] | None, wanted: list[str]) -> bool:
    if not wanted:
        return True
    if not f_cwe:
        return False
    fset = {c.upper() for c in f_cwe}
    return any(w.upper() in fset for w in wanted)


def _matches(rule: Rule, f: Finding, risk_score: int | None) -> bool:
    w = rule.when
    if f.status in set(w.exclude_status):
        return False
    if w.category_in and f.category not in set(w.category_in):
        return False
    if w.tool_in and f.source_tool not in set(w.tool_in):
        return False
    if w.rule_id_in and (f.rule_id or "") not in set(w.rule_id_in):
        return False
    if w.package_name_in and (f.package_name or "") not in set(w.package_name_in):
        return False
    if w.severity_in and not _severity_matches(f.severity_raw, w.severity_in):
        return False
    if w.cwe_any is not None and not _cwe_matches(f.cwe, w.cwe_any):
        return False
    if w.cve_present is not None:
        has_cve = bool(f.cve)
        if has_cve != w.cve_present:
            return False
    if w.min_risk_score is not None:
        # None = ainda nao pontuado; nao passa o gate
        if risk_score is None or risk_score < w.min_risk_score:
            return False
    return True


def _latest_scan(db: Session, asset_id: UUID) -> Scan | None:
    return db.scalar(
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.status == "done")
        .order_by(Scan.started_at.desc())
        .limit(1)
    )


def evaluate_policy(
    db: Session,
    asset_id: UUID,
    policy: Policy,
    scan_id: UUID | None = None,
) -> PolicyEvaluation:
    """Avalia policy contra findings 'open' do scan indicado (ou ultimo 'done')."""
    if scan_id is None:
        scan = _latest_scan(db, asset_id)
        scan_id = scan.id if scan else None

    findings: list[Finding] = []
    if scan_id is not None:
        findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.asset_id == asset_id,
                    Finding.scan_id == scan_id,
                )
            )
        )

    # risk_score por finding (mais recente)
    scores: dict[UUID, int | None] = {}
    if findings:
        ids = [f.id for f in findings]
        rows = db.execute(
            select(AIAnalysis.finding_id, AIAnalysis.risk_score)
            .where(AIAnalysis.finding_id.in_(ids))
            .order_by(AIAnalysis.created_at.desc())
        ).all()
        for fid, score in rows:
            # primeiro visto = mais recente (order by desc)
            scores.setdefault(fid, score)

    violations: list[Violation] = []
    rule_hits: dict[str, int] = {r.id: 0 for r in policy.rules}
    fail_count = 0
    warn_count = 0

    for rule in policy.rules:
        for f in findings:
            if _matches(rule, f, scores.get(f.id)):
                rule_hits[rule.id] += 1
                violations.append(
                    Violation(
                        rule_id=rule.id,
                        action=rule.action,
                        finding_id=f.id,
                        finding_title=f.title,
                        file_path=f.file_path,
                        severity=f.severity_raw,
                        risk_score=scores.get(f.id),
                        category=f.category,
                        tool=f.source_tool,
                    )
                )
                if rule.action == "fail":
                    fail_count += 1
                else:
                    warn_count += 1

    return PolicyEvaluation(
        policy_name=policy.name,
        asset_id=asset_id,
        scan_id=scan_id,
        passed=fail_count == 0,
        findings_considered=len(findings),
        fail_count=fail_count,
        warn_count=warn_count,
        violations=violations,
        rule_hits=rule_hits,
    )
