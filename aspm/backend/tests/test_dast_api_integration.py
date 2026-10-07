"""E2E via TestClient: POST /api/dast/scans → background → GET findings/report.

TestClient roda `BackgroundTasks` sincronamente apos o retorno do handler,
entao a ordem e: POST retorna → background executa → GET ve estado final.
"""
from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.dast import executor as zap_exec
from app.db import get_db
from app.main import app


_SAMPLE_REPORT = {
    "@version": "2.14.0",
    "site": [
        {
            "@name": "https://alvo.example",
            "alerts": [
                {
                    "pluginid": "40018", "name": "SQL Injection",
                    "riskcode": "3", "confidence": "3",
                    "desc": "SQLi", "solution": "parameterize",
                    "cweid": "89",
                    "instances": [
                        {"uri": "https://alvo.example/x", "method": "GET",
                         "param": "q", "evidence": "SQL error"},
                    ],
                },
            ],
        }
    ],
}


@pytest.fixture(autouse=True)
def _mock_public_dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )


@pytest.fixture()
def client(shared_db):
    """TestClient que compartilha o SQLite in-memory do shared_db fixture."""
    def _get_db():
        s = shared_db()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _get_db
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def mock_zap_success(tmp_path):
    """Mock run_zap_scan devolvendo relatorio fake OK."""
    def _fake(*, scan_id, target_url, profile, timeout_s, extra_args=None):
        workdir = tmp_path / "dast" / str(scan_id)
        workdir.mkdir(parents=True, exist_ok=True)
        report = workdir / f"zap-report-{scan_id}.json"
        report.write_text(json.dumps(_SAMPLE_REPORT), encoding="utf-8")
        return zap_exec.ExecutionResult(
            returncode=0, duration_s=10,
            report_path=report, zap_version="2.14.0",
            stdout_tail="ok", stderr_tail="",
        )
    with patch.object(zap_exec, "run_zap_scan", side_effect=_fake) as m:
        yield m


def _create_asset(client: TestClient, url="https://github.com/x/y") -> dict:
    r = client.post("/assets", json={"repo_url": url})
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------------------
# GET /api/dast/profiles
# ---------------------------------------------------------------------------


def test_profiles_endpoint_lists_four_profiles(client):
    r = client.get("/api/dast/profiles")
    assert r.status_code == 200
    names = {p["name"] for p in r.json()}
    assert names == {"passive", "baseline", "active", "full"}
    # Autorizacao expoe metadata consistente
    for p in r.json():
        if p["name"] in ("active", "full"):
            assert p["requires_authorization"] is True
        else:
            assert p["requires_authorization"] is False


# ---------------------------------------------------------------------------
# POST /api/dast/scans — validacao
# ---------------------------------------------------------------------------


def test_create_dast_scan_rejects_unknown_asset(client):
    r = client.post("/api/dast/scans", json={
        "asset_id": str(uuid.uuid4()),
        "target_url": "https://alvo.example",
        "profile": "baseline",
    })
    assert r.status_code == 404


def test_create_dast_scan_rejects_active_without_authorized(client):
    asset = _create_asset(client)
    r = client.post("/api/dast/scans", json={
        "asset_id": asset["id"],
        "target_url": "https://alvo.example",
        "profile": "active",
    })
    assert r.status_code == 400
    assert "autorizacao" in r.json()["detail"].lower()


def test_create_dast_scan_rejects_loopback_without_allow_private(client, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    asset = _create_asset(client)
    r = client.post("/api/dast/scans", json={
        "asset_id": asset["id"],
        "target_url": "http://localhost:3000",
        "profile": "baseline",
    })
    assert r.status_code == 400
    assert "url bloqueada" in r.json()["detail"].lower()


def test_create_dast_scan_rejects_invalid_profile(client):
    asset = _create_asset(client)
    r = client.post("/api/dast/scans", json={
        "asset_id": asset["id"],
        "target_url": "https://alvo.example",
        "profile": "yolo",
    })
    assert r.status_code == 422  # Pydantic pattern rejection


def test_create_dast_scan_rejects_invalid_url_scheme(client):
    asset = _create_asset(client)
    r = client.post("/api/dast/scans", json={
        "asset_id": asset["id"],
        "target_url": "file:///etc/passwd",
        "profile": "baseline",
    })
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# E2E completo: POST → background → GET endpoints
# ---------------------------------------------------------------------------


def test_full_lifecycle_scan_findings_and_report(client, mock_zap_success):
    asset = _create_asset(client)

    r = client.post("/api/dast/scans", json={
        "asset_id": asset["id"],
        "target_url": "https://alvo.example",
        "profile": "baseline",
        "requested_by": "pytest",
    })
    assert r.status_code == 202, r.text
    scan = r.json()
    scan_id = scan["id"]
    # TestClient aguarda o BackgroundTask antes do proximo request.

    # GET /api/dast/scans/{id}
    r = client.get(f"/api/dast/scans/{scan_id}")
    assert r.status_code == 200
    s = r.json()
    assert s["status"] == "completed"
    assert s["duration_s"] == 10
    assert s["zap_version"] == "2.14.0"
    assert s["findings_count"] == 1
    assert s["metrics"]["alerts"] == 1

    # GET /api/dast/scans/{id}/findings
    r = client.get(f"/api/dast/scans/{scan_id}/findings")
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "dast"
    assert f["source_tool"] == "zap"
    assert f["url"] == "https://alvo.example/x"
    assert f["http_method"] == "GET"
    assert f["parameter"] == "q"
    assert f["cwe"] == ["CWE-89"]

    # GET /api/dast/scans/{id}/report
    r = client.get(f"/api/dast/scans/{scan_id}/report")
    assert r.status_code == 200
    report = r.json()
    assert report["@version"] == "2.14.0"
    assert len(report["site"][0]["alerts"]) == 1


def test_list_scans_filters_by_asset(client, mock_zap_success):
    a1 = _create_asset(client, url="https://github.com/x/one")
    a2 = _create_asset(client, url="https://github.com/x/two")

    for asset_id in (a1["id"], a1["id"], a2["id"]):
        r = client.post("/api/dast/scans", json={
            "asset_id": asset_id,
            "target_url": "https://alvo.example",
            "profile": "baseline",
        })
        assert r.status_code == 202

    r = client.get(f"/api/dast/scans?asset_id={a1['id']}")
    assert r.status_code == 200
    scans = r.json()
    assert len(scans) == 2
    assert all(s["asset_id"] == a1["id"] for s in scans)

    r = client.get(f"/api/dast/scans?asset_id={a2['id']}")
    assert len(r.json()) == 1


def test_cancel_scan_endpoint(client, shared_db, monkeypatch):
    """Simula scan em running e chama o endpoint de cancel."""
    monkeypatch.setattr(zap_exec, "cancel_scan", lambda sid: True)

    # Cria asset + scan diretamente no DB em estado running
    from app.models import Asset, DastScan
    db = shared_db()
    try:
        asset = Asset(
            repo_url="https://x/cancel", name="svc",
            criticality_source="unknown",
        )
        db.add(asset); db.commit(); db.refresh(asset)
        scan = DastScan(
            asset_id=asset.id, target_url="https://alvo.example",
            profile="baseline", status="running",
        )
        db.add(scan); db.commit(); db.refresh(scan)
        scan_id = str(scan.id)
    finally:
        db.close()

    r = client.post(f"/api/dast/scans/{scan_id}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


def test_report_endpoint_404_when_report_absent(client, shared_db):
    from app.models import Asset, DastScan
    db = shared_db()
    try:
        asset = Asset(
            repo_url="https://x/noreport", name="svc",
            criticality_source="unknown",
        )
        db.add(asset); db.commit(); db.refresh(asset)
        scan = DastScan(
            asset_id=asset.id, target_url="https://alvo.example",
            profile="baseline", status="failed", report_path=None,
        )
        db.add(scan); db.commit(); db.refresh(scan)
        scan_id = str(scan.id)
    finally:
        db.close()

    r = client.get(f"/api/dast/scans/{scan_id}/report")
    assert r.status_code == 404


def test_findings_endpoint_404_on_unknown_scan(client):
    r = client.get(f"/api/dast/scans/{uuid.uuid4()}/findings")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Fluxo com policy engine (integracao cross-pillar)
# ---------------------------------------------------------------------------


def test_dast_policy_evaluation_flags_cwe_89(client, mock_zap_success):
    """Policy `dast` tem regra dast-top-cwes com CWE-89 → scan deve reprovar."""
    asset = _create_asset(client)

    r = client.post("/api/dast/scans", json={
        "asset_id": asset["id"],
        "target_url": "https://alvo.example",
        "profile": "baseline",
    })
    assert r.status_code == 202

    # Evaluate policy dast — regra dast-top-cwes bloqueia CWE-89
    r = client.post(
        f"/policies/dast/evaluate?asset_id={asset['id']}",
    )
    assert r.status_code == 200
    result = r.json()
    assert result["passed"] is False
    # Pelo menos uma rule hit (dast-top-cwes ou dast-high-severity)
    assert result["fail_count"] >= 1
    rules_hit = {
        v["rule_id"] for v in result["violations"]
    }
    assert "dast-top-cwes" in rules_hit or "dast-high-severity" in rules_hit
