"""Integracao do monitor DAST — ZAP daemon + polling.

Mocka subprocess (docker) e ZAPClient.alerts para evitar depender de
Docker/ZAP reais.
"""
from __future__ import annotations

import socket
import subprocess
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.core.dast import monitor as mon
from app.models import Asset, Cluster, DastMonitor, Finding, Scan


@pytest.fixture(autouse=True)
def _mock_public_dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )


@pytest.fixture()
def _no_sleep(monkeypatch):
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda *_a: None)
    monkeypatch.setattr(mon.time, "sleep", lambda *_a: None)


class _FakeCompleted:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr


def _asset(db) -> Asset:
    a = Asset(
        repo_url=f"https://x/{uuid.uuid4()}",
        name="svc", criticality=4, criticality_source="ai",
        internet_facing=True, handles_pii=True, has_auth=True,
    )
    db.add(a); db.commit(); db.refresh(a)
    return a


_SAMPLE_ALERTS = [
    {
        "pluginId": "40018", "alert": "SQL Injection", "name": "SQL Injection",
        "risk": "High", "confidence": "High",
        "description": "SQLi em q", "solution": "parameterize",
        "cweid": "89", "wascid": "19",
        "url": "https://alvo.example/search", "method": "GET",
        "param": "q", "evidence": "SQL error",
        "attack": "' OR 1=1--",
    },
    {
        "pluginId": "10038", "name": "CSP header missing",
        "risk": "Medium", "confidence": "High",
        "description": "CSP ausente", "cweid": "693",
        "url": "https://alvo.example/", "method": "GET",
    },
]


# ---------------------------------------------------------------------------
# enqueue
# ---------------------------------------------------------------------------


def test_enqueue_creates_monitor_in_starting(shared_db):
    db = shared_db()
    try:
        asset = _asset(db)
        m = mon.enqueue_monitor(
            db,
            asset_id=asset.id,
            target_url="https://alvo.example",
            poll_interval_s=30,
        )
        assert m.status == "starting"
        assert m.poll_interval_s == 30
        assert m.target_url == "https://alvo.example"
    finally:
        db.close()


def test_enqueue_clamps_interval(shared_db):
    db = shared_db()
    try:
        asset = _asset(db)
        m = mon.enqueue_monitor(
            db, asset_id=asset.id,
            target_url="https://alvo.example",
            poll_interval_s=5,  # abaixo do minimo
        )
        assert m.poll_interval_s == 15
    finally:
        db.close()


def test_enqueue_rejects_ssrf(shared_db, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    db = shared_db()
    try:
        asset = _asset(db)
        with pytest.raises(mon.SSRFError):
            mon.enqueue_monitor(
                db, asset_id=asset.id,
                target_url="http://localhost:3000",
                poll_interval_s=60,
            )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# start_monitor_task — ciclo completo com docker/zap mockados
# ---------------------------------------------------------------------------


def test_start_monitor_task_success(shared_db, monkeypatch, _no_sleep):
    monkeypatch.setattr(mon, "_is_docker_available", lambda: True)

    def _fake_run(cmd, **kw):
        return _FakeCompleted(rc=0, stdout="containerid123")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    monkeypatch.setattr(mon, "_pick_free_port", lambda: 18099)

    class _FakeZAP:
        def __init__(self, *a, **kw):
            pass

        def version(self):
            return "2.17.0"

        def spider_scan(self, url, max_children=20):
            return "0"

    monkeypatch.setattr(mon, "ZAPClient", _FakeZAP)

    db = shared_db()
    try:
        asset = _asset(db)
        m = mon.enqueue_monitor(
            db, asset_id=asset.id,
            target_url="https://alvo.example", poll_interval_s=30,
        )
        mid = m.id
    finally:
        db.close()

    mon.start_monitor_task(str(mid))

    db = shared_db()
    try:
        m = db.get(DastMonitor, mid)
        assert m.status == "running"
        assert m.zap_port == 18099
        assert m.zap_api_key is not None
        assert m.zap_container
        assert m.started_at is not None
        assert m.next_poll_at is not None
    finally:
        db.close()


def test_start_monitor_task_fails_without_docker(shared_db, monkeypatch):
    monkeypatch.setattr(mon, "_is_docker_available", lambda: False)
    db = shared_db()
    try:
        asset = _asset(db)
        m = mon.enqueue_monitor(
            db, asset_id=asset.id, target_url="https://alvo.example",
        )
        mid = m.id
    finally:
        db.close()

    mon.start_monitor_task(str(mid))

    db = shared_db()
    try:
        m = db.get(DastMonitor, mid)
        assert m.status == "failed"
        assert "docker" in (m.last_error or "").lower()
    finally:
        db.close()


def test_start_monitor_task_fails_on_zap_api_timeout(shared_db, monkeypatch, _no_sleep):
    monkeypatch.setattr(mon, "_is_docker_available", lambda: True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _FakeCompleted(rc=0))
    monkeypatch.setattr(mon, "_pick_free_port", lambda: 18099)

    class _FakeZAPDead:
        def __init__(self, *a, **kw):
            pass
        def version(self):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(mon, "ZAPClient", _FakeZAPDead)
    # Encurta timeout do wait para o teste rodar rapido
    monkeypatch.setattr(mon, "_wait_for_zap_api",
                        lambda port, api_key, timeout_s=120:
                        (_ for _ in ()).throw(mon.ZAPUnavailableError("timeout")))

    db = shared_db()
    try:
        asset = _asset(db)
        m = mon.enqueue_monitor(
            db, asset_id=asset.id, target_url="https://alvo.example",
        )
        mid = m.id
    finally:
        db.close()

    mon.start_monitor_task(str(mid))

    db = shared_db()
    try:
        m = db.get(DastMonitor, mid)
        assert m.status == "failed"
        assert "timeout" in (m.last_error or "")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# poll_monitor — nucleo do fluxo continuo
# ---------------------------------------------------------------------------


def _make_running_monitor(db, asset_id) -> DastMonitor:
    m = DastMonitor(
        asset_id=asset_id, target_url="https://alvo.example",
        status="running", zap_port=18099, zap_api_key="k",
        poll_interval_s=30, alerts_total=0, polls_total=0,
    )
    db.add(m); db.commit(); db.refresh(m)
    return m


def test_poll_monitor_normalizes_and_upserts(shared_db, monkeypatch):
    class _FakeZAP:
        def __init__(self, *a, **kw):
            pass
        def alerts(self, base_url=None):
            return _SAMPLE_ALERTS

    monkeypatch.setattr(mon, "ZAPClient", _FakeZAP)

    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        mid = m.id
        asset_id = asset.id
    finally:
        db.close()

    mon.poll_monitor(mid)

    db = shared_db()
    try:
        m = db.get(DastMonitor, mid)
        assert m.polls_total == 1
        assert m.alerts_total == 2
        assert m.last_poll_at is not None
        assert m.next_poll_at is not None
        assert m.last_error is None

        findings = list(db.scalars(
            select(Finding).where(Finding.dast_monitor_id == mid)
        ).all())
        assert len(findings) == 2
        assert all(f.category == "dast" for f in findings)
        assert all(f.source_tool == "zap" for f in findings)

        # Scan host criado com flag source=dast-monitor
        host_scans = list(db.scalars(
            select(Scan).where(Scan.asset_id == asset_id)
        ).all())
        assert len(host_scans) == 1
        assert host_scans[0].tool_stats["source"] == "dast-monitor"
    finally:
        db.close()


def test_poll_monitor_dedup_across_polls(shared_db, monkeypatch):
    """Segundo poll com mesmos alerts nao duplica."""
    class _FakeZAP:
        def __init__(self, *a, **kw):
            pass
        def alerts(self, base_url=None):
            return _SAMPLE_ALERTS

    monkeypatch.setattr(mon, "ZAPClient", _FakeZAP)

    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        mid = m.id
        asset_id = asset.id
    finally:
        db.close()

    mon.poll_monitor(mid)
    mon.poll_monitor(mid)
    mon.poll_monitor(mid)

    db = shared_db()
    try:
        m = db.get(DastMonitor, mid)
        assert m.polls_total == 3
        findings = list(db.scalars(
            select(Finding).where(Finding.asset_id == asset_id)
        ).all())
        assert len(findings) == 2
    finally:
        db.close()


def test_poll_monitor_handles_zap_api_error(shared_db, monkeypatch):
    class _BrokenZAP:
        def __init__(self, *a, **kw):
            pass
        def alerts(self, base_url=None):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(mon, "ZAPClient", _BrokenZAP)

    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        mid = m.id
    finally:
        db.close()

    mon.poll_monitor(mid)

    db = shared_db()
    try:
        m = db.get(DastMonitor, mid)
        assert m.status == "running"  # nao marca failed por falha pontual
        assert "connection refused" in (m.last_error or "")
        assert m.next_poll_at is not None  # reagenda proximo poll
    finally:
        db.close()


def test_poll_monitor_links_dast_to_existing_sast_via_cwe(shared_db, monkeypatch):
    """Monitor polling cria cluster correlator-cwe quando SAST existe com CWE-89."""
    class _FakeZAP:
        def __init__(self, *a, **kw):
            pass
        def alerts(self, base_url=None):
            return [_SAMPLE_ALERTS[0]]  # so o SQLi (CWE-89)

    monkeypatch.setattr(mon, "ZAPClient", _FakeZAP)

    db = shared_db()
    try:
        asset = _asset(db)
        sast_scan = Scan(asset_id=asset.id, status="done")
        db.add(sast_scan); db.commit(); db.refresh(sast_scan)
        sast = Finding(
            asset_id=asset.id, scan_id=sast_scan.id,
            source_tool="semgrep", category="sast",
            rule_id="python.sqli", title="SQLi",
            severity_raw="high", file_path="app/users.py",
            cwe=["CWE-89"], status="open",
            fingerprint=uuid.uuid4().hex,
        )
        db.add(sast); db.commit(); db.refresh(sast)

        m = _make_running_monitor(db, asset.id)
        mid = m.id
        sast_id = sast.id
    finally:
        db.close()

    mon.poll_monitor(mid)

    db = shared_db()
    try:
        clusters = list(db.scalars(
            select(Cluster).where(Cluster.source == "correlator-cwe")
        ).all())
        assert len(clusters) == 1
        sast_fresh = db.get(Finding, sast_id)
        assert sast_fresh.cluster_id == clusters[0].id
    finally:
        db.close()


def test_poll_monitor_noop_when_not_running(shared_db, monkeypatch):
    """Monitor com status='stopped' nao faz poll (defensive)."""
    monkeypatch.setattr(
        mon, "ZAPClient",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("nao devia chamar"))
    )
    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        m.status = "stopped"
        db.commit()
        mid = m.id
    finally:
        db.close()

    # Nao deve explodir nem chamar ZAPClient
    mon.poll_monitor(mid)


# ---------------------------------------------------------------------------
# stop / respider
# ---------------------------------------------------------------------------


def test_stop_monitor_marks_stopped_and_kills_container(shared_db, monkeypatch):
    killed = {"n": 0, "name": None}
    def _fake_run(cmd, **kw):
        if "kill" in cmd:
            killed["n"] += 1
            killed["name"] = cmd[-1]
        return _FakeCompleted(rc=0)
    monkeypatch.setattr(subprocess, "run", _fake_run)

    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        m.zap_container = "aspm-zap-monitor-test"
        db.commit()
        result = mon.stop_monitor(db, m.id)
        assert result.status == "stopped"
        assert result.stopped_at is not None
        assert killed["n"] == 1
        assert killed["name"] == "aspm-zap-monitor-test"
    finally:
        db.close()


def test_stop_monitor_noop_when_already_stopped(shared_db):
    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        m.status = "stopped"
        db.commit()
        result = mon.stop_monitor(db, m.id)
        assert result.status == "stopped"
    finally:
        db.close()


def test_respider_dispatches_spider(shared_db, monkeypatch):
    calls = {"n": 0, "url": None}

    class _FakeZAP:
        def __init__(self, *a, **kw):
            pass
        def spider_scan(self, url, max_children=20):
            calls["n"] += 1
            calls["url"] = url
            return "1"

    monkeypatch.setattr(mon, "ZAPClient", _FakeZAP)

    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        result = mon.respider_monitor(db, m.id)
        assert result.status == "running"
        assert calls["n"] == 1
        assert calls["url"] == "https://alvo.example"
    finally:
        db.close()


def test_respider_rejects_non_running(shared_db):
    db = shared_db()
    try:
        asset = _asset(db)
        m = _make_running_monitor(db, asset.id)
        m.status = "stopped"
        db.commit()
        with pytest.raises(ValueError, match="running"):
            mon.respider_monitor(db, m.id)
    finally:
        db.close()
