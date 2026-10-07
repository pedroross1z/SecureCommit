"""Schemas Pydantic para request/response da API."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl


class CreateAssetRequest(BaseModel):
    repo_url: str = Field(min_length=1, max_length=500)


class AssetOut(BaseModel):
    id: UUID
    repo_url: str
    name: str
    default_branch: str | None
    languages: dict[str, Any] | None
    frameworks: dict[str, Any] | None
    criticality: int | None
    criticality_source: str | None
    internet_facing: bool | None
    handles_pii: bool | None
    has_auth: bool | None
    ai_rationale: str | None
    owner: str | None
    created_at: datetime
    open_findings: int = 0
    max_risk_score: int | None = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: UUID
    asset_id: UUID
    commit_sha: str | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    tool_stats: dict[str, Any] | None
    error: str | None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: UUID
    asset_id: UUID
    scan_id: UUID
    source_tool: str
    category: str
    rule_id: str | None
    title: str
    description: str | None
    severity_raw: str | None
    cwe: list[str] | None
    cve: str | None
    file_path: str | None
    line_start: int | None
    line_end: int | None
    snippet: str | None
    package_name: str | None
    package_version: str | None
    fixed_version: str | None
    # Campos DAST (populados so quando category='dast')
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None
    evidence: str | None = None
    solution: str | None = None
    dast_scan_id: UUID | None = None
    dast_monitor_id: UUID | None = None
    fingerprint: str
    cluster_id: UUID | None
    status: str
    first_seen: datetime
    last_seen: datetime
    risk_score: int | None = None
    ai_rationale: str | None = None

    model_config = {"from_attributes": True}


class UpdateFindingStatusRequest(BaseModel):
    status: str = Field(pattern="^(open|triaged|false_positive|fixed|accepted_risk)$")


class RemediationOut(BaseModel):
    id: UUID
    finding_id: UUID
    patch_diff: str | None
    explanation: str | None
    breaking_risk: str | None
    test_suggestion: str | None
    applied: bool
    model: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class UpdateRemediationRequest(BaseModel):
    applied: bool


class ClusterOut(BaseModel):
    id: UUID
    asset_id: UUID
    root_cause: str
    confidence: float | None
    source: str
    created_at: datetime
    findings_count: int
    max_risk_score: int | None = None
    categories: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# DAST
# ---------------------------------------------------------------------------


class DastProfileOut(BaseModel):
    name: str
    description: str
    requires_authorization: bool
    default_timeout_s: int
    max_timeout_s: int


class CreateDastScanRequest(BaseModel):
    asset_id: UUID
    target_url: str = Field(min_length=1, max_length=2048)
    profile: str = Field(pattern="^(passive|baseline|active|full)$")
    authorized: bool = False
    requested_by: str | None = Field(default=None, max_length=200)
    options: dict[str, Any] | None = None


class DastScanOut(BaseModel):
    id: UUID
    asset_id: UUID
    target_url: str
    profile: str
    status: str
    requested_by: str | None
    authorized: bool
    options: dict[str, Any] | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_s: int | None
    zap_version: str | None
    metrics: dict[str, Any] | None
    findings_count: int
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateDastMonitorRequest(BaseModel):
    asset_id: UUID
    target_url: str = Field(min_length=1, max_length=2048)
    poll_interval_s: int = Field(default=60, ge=15, le=3600)
    options: dict[str, Any] | None = None


class DastMonitorOut(BaseModel):
    id: UUID
    asset_id: UUID
    target_url: str
    status: str
    zap_port: int | None
    poll_interval_s: int
    started_at: datetime | None
    stopped_at: datetime | None
    last_poll_at: datetime | None
    next_poll_at: datetime | None
    alerts_total: int
    polls_total: int
    last_error: str | None
    options: dict[str, Any] | None
    created_at: datetime

    model_config = {"from_attributes": True}
