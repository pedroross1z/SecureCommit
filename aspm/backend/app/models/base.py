"""SQLAlchemy models — fonte da verdade do schema.

Compativel com Postgres (producao/docker) e SQLite (dev local). Tipos
Postgres-especificos (UUID, JSONB, ARRAY) usam variantes portateis via
SQLAlchemy.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator, CHAR

from app.db import Base


class GUID(TypeDecorator):
    """UUID portavel: UUID nativo no Postgres, CHAR(36) no SQLite."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value if dialect.name == "postgresql" else str(value)
        return value if dialect.name == "postgresql" else str(uuid.UUID(str(value)))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class JSONType(TypeDecorator):
    """JSONB no Postgres, JSON no SQLite."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class StringArray(TypeDecorator):
    """TEXT[] no Postgres, JSON no SQLite (lista de strings)."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(Text))
        return dialect.type_descriptor(JSON())


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    repo_url: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    default_branch: Mapped[str | None] = mapped_column(Text)
    languages: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    frameworks: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    criticality: Mapped[int | None] = mapped_column(SmallInteger)
    criticality_source: Mapped[str | None] = mapped_column(Text)
    internet_facing: Mapped[bool | None] = mapped_column(Boolean)
    handles_pii: Mapped[bool | None] = mapped_column(Boolean)
    has_auth: Mapped[bool | None] = mapped_column(Boolean)
    ai_rationale: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scans: Mapped[list[Scan]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assets.id", ondelete="CASCADE"))
    commit_sha: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, nullable=False)  # queued|running|done|failed
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tool_stats: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    error: Mapped[str | None] = mapped_column(Text)

    asset: Mapped[Asset] = relationship(back_populates="scans")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "fingerprint", name="uq_findings_asset_fingerprint"),
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_cluster_id", "cluster_id"),
        Index("idx_findings_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("assets.id", ondelete="CASCADE"))
    scan_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="CASCADE"))
    source_tool: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)  # sast|sca|secret|iac|container
    rule_id: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity_raw: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[list[str] | None] = mapped_column(StringArray)
    cve: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(Text)
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    snippet: Mapped[str | None] = mapped_column(Text)
    package_name: Mapped[str | None] = mapped_column(Text)
    package_version: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(Text)
    # Campos opcionais do DAST — populados apenas quando source_tool='zap' / category='dast'.
    url: Mapped[str | None] = mapped_column(Text)
    http_method: Mapped[str | None] = mapped_column(Text)
    parameter: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    solution: Mapped[str | None] = mapped_column(Text)
    dast_scan_id: Mapped[uuid.UUID | None] = mapped_column(GUID())
    dast_monitor_id: Mapped[uuid.UUID | None] = mapped_column(GUID())
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    cluster_id: Mapped[uuid.UUID | None] = mapped_column(GUID())
    status: Mapped[str] = mapped_column(Text, default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped[Asset] = relationship(back_populates="findings")


class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    finding_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    reachability: Mapped[str | None] = mapped_column(Text)  # reachable|unreachable|unknown
    exploitability: Mapped[int | None] = mapped_column(SmallInteger)
    business_impact: Mapped[int | None] = mapped_column(SmallInteger)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    is_likely_false_positive: Mapped[bool | None] = mapped_column(Boolean)
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    prompt_version: Mapped[str] = mapped_column(Text, nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    finding_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    patch_diff: Mapped[str | None] = mapped_column(Text)
    explanation: Mapped[str | None] = mapped_column(Text)
    breaking_risk: Mapped[str | None] = mapped_column(Text)  # low|medium|high
    test_suggestion: Mapped[str | None] = mapped_column(Text)
    applied: Mapped[bool] = mapped_column(Boolean, default=False)
    model: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AICache(Base):
    __tablename__ = "ai_cache"

    cache_key: Mapped[str] = mapped_column(Text, primary_key=True)
    response: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Cluster(Base):
    __tablename__ = "clusters"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
    source: Mapped[str] = mapped_column(Text, default="ai")  # ai|manual
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DastMonitor(Base):
    """Monitor DAST contínuo: ZAP daemon persistente apontado para um alvo.

    Diferente de `DastScan` (one-shot), um monitor fica rodando: o backend
    polla a API do ZAP em cadência (`poll_interval_s`) buscando alertas
    novos e normaliza como findings. Pode ser pausado/retomado.
    """

    __tablename__ = "dast_monitors"
    __table_args__ = (
        Index("idx_dast_monitors_asset_id", "asset_id"),
        Index("idx_dast_monitors_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="CASCADE")
    )
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    # starting | running | stopped | failed
    status: Mapped[str] = mapped_column(Text, nullable=False, default="starting")
    zap_container: Mapped[str | None] = mapped_column(Text)
    zap_port: Mapped[int | None] = mapped_column(Integer)
    zap_api_key: Mapped[str | None] = mapped_column(Text)
    poll_interval_s: Mapped[int] = mapped_column(Integer, default=60)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerts_total: Mapped[int] = mapped_column(Integer, default=0)
    polls_total: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    options: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class DastScan(Base):
    """Execução DAST (OWASP ZAP). Independe do Scan de código-fonte."""

    __tablename__ = "dast_scans"
    __table_args__ = (
        Index("idx_dast_scans_asset_id", "asset_id"),
        Index("idx_dast_scans_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="CASCADE")
    )
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    profile: Mapped[str] = mapped_column(Text, nullable=False)  # passive|baseline|active|full
    # pending|queued|running|completed|failed|cancelled
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    requested_by: Mapped[str | None] = mapped_column(Text)
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    options: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_s: Mapped[int | None] = mapped_column(Integer)
    zap_version: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    report_path: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
