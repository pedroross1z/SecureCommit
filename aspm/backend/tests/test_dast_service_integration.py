"""Integracao do service DAST — fluxo completo com executor mockado.

Mocka `zap_exec.run_zap_scan` para evitar depender de Docker; o resto do
pipeline (parse, normalize, upsert, correlator) roda de verdade contra
SQLite in-memory compartilhado via `shared_db`.
"""
from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.core.dast import executor as zap_exec
from app.core.dast import service as dast_service
from app.models import Asset, Cluster, DastScan, Finding, Scan


@pytest.fixture(autouse=True)
def _mock_public_dns(monkeypatch):
    """SSRF guard resolve DNS para validar IPs — mockamos para um IP publico."""
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SAMPLE_ZAP_REPORT = {
    "@version": "2.14.0",
    "site": [
        {
            "@name": "https://alvo.example",
            "alerts": [
                {
                    "pluginid": "40018",
                    "alertRef": "40018",
                    "alert": "SQL Injection",
                    "name": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "3",
                    "desc": "SQLi detectada no parametro q",
                    "solution": "Use prepared statements",
                    "cweid": "89",
                    "wascid": "19",
                    "instances": [
                        {
                            "uri": "https://alvo.example/search",
                            "method": "GET",
                            "param": "q",
                            "evidence": "SQL syntax error",
                            "attack": "' OR 1=1--",
                        },
                        {
                            "uri": "https://alvo.example/login",
                            "method": "POST",
                            "param": "username",
                            "evidence": "SQL syntax error",
                        },
                    ],
                },
                {
                    "pluginid": "10038",
                    "name": "Content Security Policy Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "CSP ausente",
                    "cweid": "693",
                    "instances": [
                        {"uri": "https://alvo.example/", "method": "GET"},
                    ],
                },
            ],
        }
    ],
}


def _write_report(tmp_path: Path, scan_id: uuid.UUID) -> Path:
    """Grava um relatorio ZAP fake no formato esperado pelo executor."""
    workdir = tmp_path / "dast" / str(scan_id)
    workdir.mkdir(parents=True, exist_ok=True)
    report = workdir / f"zap-report-{scan_id}.json"
    report.write_text(
        json.dumps(_SAMPLE_ZAP_REPORT), encoding="utf-8"
    )
    return report


def _make_asset(db) -> Asset:
    a = Asset(
        repo_url=f"https://x/{uuid.uuid4()}",
        name="svc", criticality=4,
        criticality_source="ai", internet_facing=True,
        handles_pii=True, has_auth=True,
    )
    db.add(a); db.commit(); db.refresh(a)
    return a


def _make_dast_scan(
    db, asset_id, *, profile="baseline", target_url="https://alvo.example",
    authorized=False, options=None,
) -> DastScan:
    s = DastScan(
        asset_id=asset_id, target_url=target_url, profile=profile,
        status="queued", authorized=authorized, options=options or {},
    )
    db.add(s); db.commit(); db.refresh(s)
    return s


def _mock_executor_success(tmp_path: Path):
    """Context mocando run_zap_scan para devolver sucesso com report fake."""
    def _fake(*, scan_id, target_url, profile, timeout_s, extra_args=None):
        report = _write_report(tmp_path, scan_id)
        return zap_exec.ExecutionResult(
            returncode=0, duration_s=12,
            report_path=report, zap_version="2.14.0",
            stdout_tail="scan completed", stderr_tail="",
        )
    return patch.object(zap_exec, "run_zap_scan", side_effect=_fake)


# ---------------------------------------------------------------------------
# Fluxo completo
# ---------------------------------------------------------------------------


def test_full_scan_completes_and_populates_findings(shared_db, tmp_path):
    db = shared_db()
    try:
        asset = _make_asset(db)
        asset_id = asset.id
        scan = _make_dast_scan(db, asset_id)
        scan_id = scan.id
    finally:
        db.close()

    with _mock_executor_success(tmp_path):
        dast_service.run_dast_scan_task(str(scan_id))

    db = shared_db()
    try:
        s = db.get(DastScan, scan_id)
        assert s is not None
        assert s.status == "completed"
        assert s.started_at is not None
        assert s.finished_at is not None
        assert s.duration_s == 12
        assert s.zap_version == "2.14.0"
        assert s.error is None
        assert s.report_path and Path(s.report_path).exists()
        # findings_count = SQLi(2 instancias) + CSP(1) = 3
        assert s.findings_count == 3

        metrics = s.metrics
        assert metrics["alerts"] == 2
        assert metrics["unique_urls"] == 3
        assert metrics["by_severity"]["high"] == 1
        assert metrics["new"] == 3
        assert metrics["updated"] == 0
        assert metrics["executor_rc"] == 0
        # correlator rodou mesmo sem SAST par (so registra stats zeradas)
        assert "correlator" in metrics

        # Scan host criado com flag source=dast
        host_scans = list(db.scalars(
            select(Scan).where(Scan.asset_id == asset_id)
        ).all())
        assert len(host_scans) == 1
        assert host_scans[0].tool_stats["source"] == "dast"

        # Findings persistidos com category=dast, source_tool=zap
        findings = list(db.scalars(
            select(Finding).where(Finding.dast_scan_id == scan_id)
        ).all())
        assert len(findings) == 3
        assert all(f.category == "dast" for f in findings)
        assert all(f.source_tool == "zap" for f in findings)
        # URLs e metodos preservados
        urls = {f.url for f in findings}
        assert "https://alvo.example/search" in urls
        assert "https://alvo.example/login" in urls
    finally:
        db.close()


def test_rescan_updates_existing_findings(shared_db, tmp_path):
    """Segunda execucao com mesmo relatorio nao duplica — soma em metrics.updated."""
    db = shared_db()
    try:
        asset = _make_asset(db)
        asset_id = asset.id
        first = _make_dast_scan(db, asset.id)
        first_id = first.id
    finally:
        db.close()

    with _mock_executor_success(tmp_path):
        dast_service.run_dast_scan_task(str(first_id))

    db = shared_db()
    try:
        second = _make_dast_scan(db, asset_id)
        second_id = second.id
    finally:
        db.close()

    with _mock_executor_success(tmp_path):
        dast_service.run_dast_scan_task(str(second_id))

    db = shared_db()
    try:
        s2 = db.get(DastScan, second_id)
        assert s2.status == "completed"
        # Mesmos 3 fingerprints → 0 novos, 3 atualizados
        assert s2.metrics["new"] == 0
        assert s2.metrics["updated"] == 3

        # Nenhum finding duplicado no asset
        all_findings = list(db.scalars(
            select(Finding).where(Finding.asset_id == asset_id)
        ).all())
        assert len(all_findings) == 3
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Correlator DAST↔SAST integrado
# ---------------------------------------------------------------------------


def test_scan_links_dast_to_existing_sast_via_cwe(shared_db, tmp_path):
    """SAST pre-existente com CWE-89 deve ser agrupado com o DAST SQLi via correlator."""
    db = shared_db()
    try:
        asset = _make_asset(db)
        # Scan SAST pre-existente
        sast_scan = Scan(asset_id=asset.id, status="done")
        db.add(sast_scan); db.commit(); db.refresh(sast_scan)
        sast = Finding(
            asset_id=asset.id, scan_id=sast_scan.id,
            source_tool="semgrep", category="sast",
            rule_id="python.sqli", title="SQLi em user_queries",
            severity_raw="high", file_path="app/users.py",
            cwe=["CWE-89"], status="open",
            fingerprint=uuid.uuid4().hex,
        )
        db.add(sast); db.commit(); db.refresh(sast)

        dast_scan = _make_dast_scan(db, asset.id)
        dast_scan_id = dast_scan.id
        sast_id = sast.id
    finally:
        db.close()

    with _mock_executor_success(tmp_path):
        dast_service.run_dast_scan_task(str(dast_scan_id))

    db = shared_db()
    try:
        # Verifica cluster correlator-cwe criado
        clusters = list(db.scalars(
            select(Cluster).where(Cluster.source == "correlator-cwe")
        ).all())
        assert len(clusters) == 1
        cluster = clusters[0]
        assert "SQL" in cluster.root_cause

        # SAST foi migrado para o cluster
        db.refresh_from = None  # noqa
        sast_fresh = db.get(Finding, sast_id)
        assert sast_fresh.cluster_id == cluster.id

        # Pelo menos os 2 DAST SQLi (CWE-89) estao no cluster
        dast_in_cluster = list(db.scalars(
            select(Finding).where(
                Finding.cluster_id == cluster.id,
                Finding.category == "dast",
            )
        ).all())
        assert len(dast_in_cluster) == 2  # 2 instancias de CWE-89

        # metrics.correlator reflete o resultado
        s = db.get(DastScan, dast_scan_id)
        corr = s.metrics["correlator"]
        assert corr["cwes_examined"] >= 1
        assert corr["clusters_created"] == 1
        assert corr["dast_findings_linked"] == 2
        assert corr["sast_findings_linked"] == 1
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Falhas operacionais
# ---------------------------------------------------------------------------


def test_scan_fails_when_zap_unavailable(shared_db, tmp_path):
    db = shared_db()
    try:
        asset = _make_asset(db)
        scan = _make_dast_scan(db, asset.id)
        scan_id = scan.id
    finally:
        db.close()

    with patch.object(
        zap_exec, "run_zap_scan",
        side_effect=zap_exec.ZAPUnavailableError("docker fora"),
    ):
        dast_service.run_dast_scan_task(str(scan_id))

    db = shared_db()
    try:
        s = db.get(DastScan, scan_id)
        assert s.status == "failed"
        assert "docker fora" in (s.error or "")
        assert s.finished_at is not None
    finally:
        db.close()


def test_scan_fails_on_timeout(shared_db, tmp_path):
    db = shared_db()
    try:
        asset = _make_asset(db)
        scan = _make_dast_scan(db, asset.id)
        scan_id = scan.id
    finally:
        db.close()

    with patch.object(
        zap_exec, "run_zap_scan",
        side_effect=TimeoutError("excedeu 300s"),
    ):
        dast_service.run_dast_scan_task(str(scan_id))

    db = shared_db()
    try:
        s = db.get(DastScan, scan_id)
        assert s.status == "failed"
        assert "excedeu" in (s.error or "")
    finally:
        db.close()


def test_scan_fails_when_report_missing(shared_db):
    db = shared_db()
    try:
        asset = _make_asset(db)
        scan = _make_dast_scan(db, asset.id)
        scan_id = scan.id
    finally:
        db.close()

    def _fake_no_report(*, scan_id, target_url, profile, timeout_s, extra_args=None):
        return zap_exec.ExecutionResult(
            returncode=2, duration_s=5,
            report_path=None, zap_version=None,
            stdout_tail="", stderr_tail="ERRO: alvo nao responde",
        )

    with patch.object(zap_exec, "run_zap_scan", side_effect=_fake_no_report):
        dast_service.run_dast_scan_task(str(scan_id))

    db = shared_db()
    try:
        s = db.get(DastScan, scan_id)
        assert s.status == "failed"
        assert "sem relatorio" in (s.error or "")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Gate SSRF server-side (dentro do service)
# ---------------------------------------------------------------------------


def test_scan_blocked_by_ssrf_before_executor(shared_db, monkeypatch):
    """URL de loopback sem allow_private deve falhar antes de chamar o executor."""
    db = shared_db()
    try:
        asset = _make_asset(db)
        # Enqueue direto no DB para bular validacao do enqueue (que ja bloqueia)
        scan = DastScan(
            asset_id=asset.id,
            target_url="http://localhost:3000",
            profile="baseline", status="queued", authorized=False,
            options={},
        )
        db.add(scan); db.commit(); db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    # Override o mock global para resolver loopback neste teste
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    # Garante que executor nao e chamado
    called = {"n": 0}
    def _fail(*a, **kw):
        called["n"] += 1
        raise AssertionError("executor nao devia ser chamado")
    monkeypatch.setattr(zap_exec, "run_zap_scan", _fail)

    dast_service.run_dast_scan_task(str(scan_id))

    db = shared_db()
    try:
        s = db.get(DastScan, scan_id)
        assert s.status == "failed"
        assert "ssrf" in (s.error or "").lower()
    finally:
        db.close()
    assert called["n"] == 0


# ---------------------------------------------------------------------------
# Autorizacao
# ---------------------------------------------------------------------------


def test_enqueue_rejects_active_without_authorized(shared_db):
    """Autorizacao server-side nunca confia no front; checa aqui o enqueue path."""
    db = shared_db()
    try:
        asset = _make_asset(db)
        with pytest.raises(ValueError, match="autorizacao"):
            dast_service.enqueue_dast_scan(
                db,
                asset_id=asset.id,
                target_url="https://alvo.example",
                profile_name="active",
                authorized=False,
                options=None,
                requested_by="test",
            )
    finally:
        db.close()


def test_enqueue_accepts_active_with_authorized(shared_db, monkeypatch):
    import socket
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    db = shared_db()
    try:
        asset = _make_asset(db)
        scan = dast_service.enqueue_dast_scan(
            db,
            asset_id=asset.id,
            target_url="https://alvo.example",
            profile_name="active",
            authorized=True,
            options=None,
            requested_by="test",
        )
        assert scan.status == "queued"
        assert scan.authorized is True
        assert scan.profile == "active"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------


def test_cancel_marks_scan_cancelled(shared_db, monkeypatch):
    monkeypatch.setattr(zap_exec, "cancel_scan", lambda sid: True)
    db = shared_db()
    try:
        asset = _make_asset(db)
        scan = _make_dast_scan(db, asset.id)
        scan.status = "running"
        db.commit()

        result = dast_service.cancel_dast_scan(db, scan.id)
        assert result.status == "cancelled"
        assert result.finished_at is not None
    finally:
        db.close()


def test_cancel_noop_on_terminal_state(shared_db, monkeypatch):
    monkeypatch.setattr(zap_exec, "cancel_scan", lambda sid: True)
    db = shared_db()
    try:
        asset = _make_asset(db)
        scan = _make_dast_scan(db, asset.id)
        scan.status = "completed"
        db.commit()

        result = dast_service.cancel_dast_scan(db, scan.id)
        assert result.status == "completed"
    finally:
        db.close()
