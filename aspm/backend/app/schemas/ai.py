"""Schemas Pydantic para saidas de IA — cada chamada tem contrato explicito."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


ServiceType = Literal["api", "frontend", "worker", "library", "cli", "unknown"]


class DiscoveryContext(BaseModel):
    """Saida do prompt de descoberta de contexto de asset (Pilar 1)."""

    service_type: ServiceType
    criticality: int = Field(ge=1, le=5)
    internet_facing: bool
    handles_pii: bool
    has_auth: bool
    rationale: str = Field(min_length=1, max_length=2000)


class TriageResult(BaseModel):
    """Saida da triagem em lote (Pilar 4, estagio 1)."""

    finding_id: str
    reachability: Literal["reachable", "unreachable", "unknown"]
    exploitability: int = Field(ge=1, le=5)
    business_impact: int = Field(ge=1, le=5)
    is_likely_false_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=1000)


class TriageBatch(BaseModel):
    results: list[TriageResult]


class DeepAnalysisResult(BaseModel):
    """Saida do estagio 2 (Sonnet, arquivo completo)."""

    reachability: Literal["reachable", "unreachable", "unknown"]
    exploitability: int = Field(ge=1, le=5)
    business_impact: int = Field(ge=1, le=5)
    is_likely_false_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class ClusterProposal(BaseModel):
    finding_ids: list[str]
    root_cause: str
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("finding_ids")
    @classmethod
    def at_least_two(cls, v: list[str]) -> list[str]:
        if len(v) < 2:
            raise ValueError("cluster precisa de pelo menos 2 findings")
        return v


class ClusterResponse(BaseModel):
    clusters: list[ClusterProposal]


class RemediationOutput(BaseModel):
    patch_diff: str
    explanation: str
    breaking_risk: Literal["low", "medium", "high"]
    test_suggestion: str
