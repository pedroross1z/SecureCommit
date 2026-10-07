"""Correlator DAST ↔ SAST — deterministico, por CWE compartilhado.

A ideia: um alert DAST (ex.: SQLi em POST /login?username) raramente eh
coincidencia com um finding SAST do mesmo CWE no mesmo asset (ex.: query
nao parametrizada em `users.py`). Agrupamos os dois num cluster para o
analista ver "sintoma + raiz" lado a lado.

Diferente de `app/core/correlator.py` (que usa IA e so olha findings de um
unico scan), este correlator:
- opera cross-scan dentro do mesmo asset
- eh deterministico (zero chamadas IA) → sem custo, auditavel
- preserva clusters existentes: se SAST matched ja esta em um cluster,
  o DAST novo e atribuido a ESSE cluster; nunca re-cluster SAST
- so trata CWEs com alto sinal de correlacao (SQLi, XSS, SSRF, RCE, etc)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Cluster, Finding

logger = logging.getLogger("aspm.dast.correlator")

# CWEs cuja aparicao em DAST + SAST tipicamente indica a mesma vuln.
# Normalizamos para "CWE-N" (uppercase) para match case-insensitive.
_CORRELATABLE_CWES: frozenset[str] = frozenset({
    "CWE-77",   # Command Injection (generic)
    "CWE-78",   # OS Command Injection
    "CWE-79",   # XSS
    "CWE-89",   # SQL Injection
    "CWE-94",   # Code Injection
    "CWE-22",   # Path Traversal
    "CWE-611",  # XXE
    "CWE-918",  # SSRF
    "CWE-352",  # CSRF
    "CWE-287",  # Improper Authentication
    "CWE-306",  # Missing Authentication
    "CWE-434",  # Unrestricted Upload
    "CWE-502",  # Insecure Deserialization
    "CWE-601",  # Open Redirect
    "CWE-798",  # Hardcoded Credentials
})

_ROOT_CAUSE_LABEL = {
    "CWE-77":  "Command injection (DAST confirma SAST)",
    "CWE-78":  "OS command injection (DAST confirma SAST)",
    "CWE-79":  "XSS (DAST confirma SAST)",
    "CWE-89":  "SQL injection (DAST confirma SAST)",
    "CWE-94":  "Code injection (DAST confirma SAST)",
    "CWE-22":  "Path traversal (DAST confirma SAST)",
    "CWE-611": "XXE (DAST confirma SAST)",
    "CWE-918": "SSRF (DAST confirma SAST)",
    "CWE-352": "CSRF (DAST confirma SAST)",
    "CWE-287": "Falha de autenticacao (DAST confirma SAST)",
    "CWE-306": "Autenticacao ausente (DAST confirma SAST)",
    "CWE-434": "Upload irrestrito (DAST confirma SAST)",
    "CWE-502": "Deserializacao insegura (DAST confirma SAST)",
    "CWE-601": "Open redirect (DAST confirma SAST)",
    "CWE-798": "Credenciais hardcoded (DAST confirma SAST)",
}

_SOURCE_TAG = "correlator-cwe"


@dataclass
class CrossCorrelationStats:
    cwes_examined: int = 0
    clusters_created: int = 0
    clusters_reused: int = 0
    dast_findings_linked: int = 0
    sast_findings_linked: int = 0


def _normalize_cwes(cwes: list[str] | None) -> set[str]:
    if not cwes:
        return set()
    return {c.strip().upper() for c in cwes if c and c.strip()}


def _correlatable_cwes(f: Finding) -> set[str]:
    return _normalize_cwes(f.cwe) & _CORRELATABLE_CWES


def _fetch_dast_findings(db: Session, dast_scan_id: UUID) -> list[Finding]:
    """DAST findings do scan atual sem cluster. Reclusterizar quebraria contratos."""
    stmt = (
        select(Finding)
        .where(
            Finding.dast_scan_id == dast_scan_id,
            Finding.category == "dast",
            Finding.cluster_id.is_(None),
            Finding.status == "open",
        )
    )
    return list(db.scalars(stmt).all())


def _fetch_sast_matches(
    db: Session, asset_id: UUID, cwe: str
) -> list[Finding]:
    """Findings SAST abertos do asset cujo CWE inclui `cwe` (case-insensitive)."""
    # SQLite nao tem operador ANY em array JSON; filtramos em Python apos
    # buscar os candidatos. Como o volume por asset eh pequeno, OK.
    stmt = (
        select(Finding)
        .where(
            Finding.asset_id == asset_id,
            Finding.category != "dast",
            Finding.status == "open",
            Finding.cwe.is_not(None),
        )
    )
    rows = db.scalars(stmt).all()
    return [f for f in rows if cwe in _normalize_cwes(f.cwe)]


def _pick_existing_cluster(matches: list[Finding]) -> UUID | None:
    """Se TODOS os SAST matched com cluster_id apontam para o mesmo cluster, reusa-o.

    Se divergem (findings em clusters diferentes), nao fundimos — retornamos
    None e deixamos o chamador criar cluster novo apenas com os sem cluster.
    """
    cluster_ids = {f.cluster_id for f in matches if f.cluster_id is not None}
    if not cluster_ids:
        return None
    if len(cluster_ids) > 1:
        return None
    return next(iter(cluster_ids))


def correlate_dast_sast(
    db: Session,
    asset_id: UUID,
    dast_scan_id: UUID,
) -> CrossCorrelationStats:
    """Correlaciona findings DAST novos com SAST existentes por CWE comum.

    Retorna stats para registro em `dast_scans.metrics`. Nunca levanta — se
    nao houver nada a correlacionar, retorna stats zeradas.
    """
    stats = CrossCorrelationStats()

    dast_findings = _fetch_dast_findings(db, dast_scan_id)
    if not dast_findings:
        return stats

    # Agrupa DAST findings por CWE correlacionavel.
    by_cwe: dict[str, list[Finding]] = {}
    for f in dast_findings:
        for cwe in _correlatable_cwes(f):
            by_cwe.setdefault(cwe, []).append(f)

    if not by_cwe:
        return stats

    for cwe, dast_group in by_cwe.items():
        stats.cwes_examined += 1
        sast_matches = _fetch_sast_matches(db, asset_id, cwe)
        if not sast_matches:
            continue  # DAST sozinho — nao forma par

        existing_cluster_id = _pick_existing_cluster(sast_matches)

        if existing_cluster_id is not None:
            cluster_id = existing_cluster_id
            stats.clusters_reused += 1
            logger.info(
                "dast correlator: %s reusa cluster %s (asset %s)",
                cwe, cluster_id, asset_id,
            )
        else:
            cluster = Cluster(
                asset_id=asset_id,
                root_cause=_ROOT_CAUSE_LABEL.get(cwe, f"{cwe} correlacionado DAST↔SAST"),
                confidence=0.85,  # heuristica deterministica, nao probabilidade
                source=_SOURCE_TAG,
            )
            db.add(cluster)
            db.flush()
            cluster_id = cluster.id
            stats.clusters_created += 1
            logger.info(
                "dast correlator: criou cluster %s para %s (asset %s)",
                cluster_id, cwe, asset_id,
            )

            # Migra SAST sem cluster para o novo cluster. Nao mexe nos que ja
            # tem cluster_id — isso quebraria clusters previos.
            for sf in sast_matches:
                if sf.cluster_id is None:
                    sf.cluster_id = cluster_id
                    stats.sast_findings_linked += 1

        # Finalmente, aponta os DAST deste CWE para o cluster escolhido.
        for df in dast_group:
            if df.cluster_id is None:
                df.cluster_id = cluster_id
                stats.dast_findings_linked += 1

    db.commit()
    logger.info(
        "dast correlator: %d cwe(s), %d novos, %d reusados, %d DAST + %d SAST linkados",
        stats.cwes_examined, stats.clusters_created, stats.clusters_reused,
        stats.dast_findings_linked, stats.sast_findings_linked,
    )
    return stats
