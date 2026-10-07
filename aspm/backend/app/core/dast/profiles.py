"""Perfis de execucao DAST.

Perfis determinam qual script do ZAP e executado e com que intensidade.
`passive` e `baseline` sao sempre seguros; `active` e `full` so rodam com
autorizacao explicita (payload.authorized=True) e so em alvos autorizados.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Profile = Literal["passive", "baseline", "active", "full"]


@dataclass(frozen=True)
class ProfileSpec:
    name: Profile
    description: str
    zap_script: str          # script dentro do container zap-stable
    requires_authorization: bool
    default_timeout_s: int
    max_timeout_s: int
    # Flag ligada no script zap-baseline.py para desabilitar active (-s).
    passive_only: bool = False


_PROFILES: dict[str, ProfileSpec] = {
    "passive": ProfileSpec(
        name="passive",
        description="Spider + analise passiva (sem payloads ofensivos). Mais seguro.",
        zap_script="zap-baseline.py",
        requires_authorization=False,
        default_timeout_s=600,
        max_timeout_s=1800,
        passive_only=True,
    ),
    "baseline": ProfileSpec(
        name="baseline",
        description="Baseline oficial do ZAP: spider + passive. Produz relatorio JSON.",
        zap_script="zap-baseline.py",
        requires_authorization=False,
        default_timeout_s=900,
        max_timeout_s=1800,
    ),
    "active": ProfileSpec(
        name="active",
        description="Active scan — envia payloads ofensivos. REQUER autorizacao explicita.",
        zap_script="zap-full-scan.py",
        requires_authorization=True,
        default_timeout_s=1800,
        max_timeout_s=3600,
    ),
    "full": ProfileSpec(
        name="full",
        description="Full scan — descoberta profunda + passive + active. REQUER autorizacao.",
        zap_script="zap-full-scan.py",
        requires_authorization=True,
        default_timeout_s=3600,
        max_timeout_s=7200,
    ),
}


def get_profile(name: str) -> ProfileSpec:
    key = (name or "").lower().strip()
    spec = _PROFILES.get(key)
    if spec is None:
        valid = ", ".join(_PROFILES.keys())
        raise ValueError(f"perfil invalido: {name!r}; use um de: {valid}")
    return spec


def list_profiles() -> list[ProfileSpec]:
    return list(_PROFILES.values())
