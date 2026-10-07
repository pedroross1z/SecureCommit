"""Testes end-to-end do CI gate `aspm_gate.py`.

Mocka a API via httpx.MockTransport para exercitar o fluxo completo sem
precisar levantar o backend ou o Docker.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

_GATE_PATH = Path(__file__).resolve().parents[1] / "bin" / "aspm_gate.py"


def _load_gate():
    """Importa aspm_gate.py como modulo (nao esta em pacote)."""
    spec = importlib.util.spec_from_file_location("aspm_gate", _GATE_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aspm_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _ApiFake:
    """Rota chamadas httpx -> handlers por metodo+path."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self.sast_states = ["running", "done"]
        self.dast_states = ["running", "completed"]
        self.sast_id = "11111111-1111-1111-1111-111111111111"
        self.dast_id = "22222222-2222-2222-2222-222222222222"
        self.eval_result: dict[str, Any] = {
            "policy_name": "default",
            "asset_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "scan_id": self.sast_id,
            "passed": True,
            "findings_considered": 0,
            "fail_count": 0,
            "warn_count": 0,
            "violations": [],
            "rule_hits": {},
        }
        self.dast_error: str | None = None

    def handle(self, request: httpx.Request) -> httpx.Response:
        body: dict | None = None
        if request.content:
            try:
                body = json.loads(request.content)
            except Exception:
                body = None
        self.calls.append((request.method, request.url.path, body))

        path = request.url.path
        # SAST
        if request.method == "POST" and path.startswith("/assets/") and path.endswith("/scan"):
            return httpx.Response(202, json={"id": self.sast_id, "status": "queued"})
        if request.method == "GET" and path.startswith("/scans/"):
            st = self.sast_states.pop(0) if self.sast_states else "done"
            return httpx.Response(200, json={"id": self.sast_id, "status": st, "error": None})
        # DAST
        if request.method == "POST" and path == "/api/dast/scans":
            # Simula validacao do backend
            if body:
                if body.get("profile") in ("active", "full") and not body.get("authorized"):
                    return httpx.Response(
                        400,
                        json={"detail": "perfil requer autorizacao explicita"},
                    )
            return httpx.Response(202, json={"id": self.dast_id, "status": "queued"})
        if request.method == "GET" and path.startswith("/api/dast/scans/"):
            st = self.dast_states.pop(0) if self.dast_states else "completed"
            return httpx.Response(
                200,
                json={
                    "id": self.dast_id,
                    "status": st,
                    "error": self.dast_error if st == "failed" else None,
                },
            )
        # Policy
        if request.method == "POST" and path.startswith("/policies/") and path.endswith("/evaluate"):
            return httpx.Response(200, json=self.eval_result)

        return httpx.Response(404, json={"detail": f"no route: {request.method} {path}"})


@pytest.fixture()
def api(monkeypatch) -> _ApiFake:
    fake = _ApiFake()
    original_client = httpx.Client

    def _patched_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handle)
        return original_client(*args, **kwargs)

    monkeypatch.setattr(gate.httpx, "Client", _patched_client)
    # Timeouts curtos nos sleeps para o teste rodar rapido.
    monkeypatch.setattr(gate.time, "sleep", lambda s: None)
    return fake


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


def test_argparse_requires_asset_id():
    with pytest.raises(SystemExit) as e:
        gate._build_parser().parse_args([])
    assert e.value.code == 2


def test_argparse_defaults():
    ns = gate._build_parser().parse_args(["--asset-id", "a"])
    assert ns.policy == "default"
    assert ns.dast_profile == "baseline"
    assert ns.dast_authorized is False
    assert ns.dast_url is None


def test_argparse_rejects_invalid_profile():
    with pytest.raises(SystemExit):
        gate._build_parser().parse_args(
            ["--asset-id", "a", "--dast-profile", "yolo"]
        )


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_pass_returns_zero(api, capsys):
    rc = gate.main(
        ["--api-url", "http://x", "--asset-id", "aaaa", "--policy", "default"]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out


def test_fail_returns_one(api, capsys):
    api.eval_result["passed"] = False
    api.eval_result["fail_count"] = 2
    api.eval_result["violations"] = [
        {
            "rule_id": "r1", "action": "fail",
            "finding_id": "x", "finding_title": "SQLi em /login",
            "file_path": "https://alvo/login", "severity": "high",
            "risk_score": 85, "category": "dast", "tool": "zap",
        }
    ]
    rc = gate.main(["--api-url", "http://x", "--asset-id", "aaaa"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "SQLi em /login" in out


# ---------------------------------------------------------------------------
# SAST --wait
# ---------------------------------------------------------------------------


def test_wait_starts_scan_and_polls(api):
    gate.main(["--api-url", "http://x", "--asset-id", "aaaa", "--wait"])
    paths = [p for _, p, _ in api.calls]
    assert any(p.endswith("/scan") for p in paths)       # POST /assets/{id}/scan
    assert any(p.startswith("/scans/") for p in paths)   # polling


def test_wait_fails_operationally_on_scan_failed(api, monkeypatch):
    api.sast_states = ["running", "failed"]
    with pytest.raises(SystemExit) as e:
        gate.main(["--api-url", "http://x", "--asset-id", "aaaa", "--wait"])
    assert e.value.code == 2


# ---------------------------------------------------------------------------
# DAST
# ---------------------------------------------------------------------------


def test_dast_url_triggers_dast_scan(api):
    gate.main([
        "--api-url", "http://x", "--asset-id", "aaaa",
        "--dast-url", "https://staging.example.com",
        "--dast-profile", "baseline",
    ])
    posts = [b for m, p, b in api.calls if m == "POST" and p == "/api/dast/scans"]
    assert len(posts) == 1
    body = posts[0]
    assert body["target_url"] == "https://staging.example.com"
    assert body["profile"] == "baseline"
    assert body["authorized"] is False
    # Default: tem polling do dast
    assert any(p.startswith("/api/dast/scans/") for m, p, _ in api.calls if m == "GET")


def test_dast_active_requires_authorized(api):
    # Backend fake retorna 400 quando active sem authorized.
    with pytest.raises(SystemExit) as e:
        gate.main([
            "--api-url", "http://x", "--asset-id", "aaaa",
            "--dast-url", "https://staging.example.com",
            "--dast-profile", "active",
        ])
    assert e.value.code == 2  # erro operacional, nao reprovacao


def test_dast_active_passes_authorized_flag(api):
    gate.main([
        "--api-url", "http://x", "--asset-id", "aaaa",
        "--dast-url", "https://staging.example.com",
        "--dast-profile", "active",
        "--dast-authorized",
    ])
    body = next(b for m, p, b in api.calls if m == "POST" and p == "/api/dast/scans")
    assert body["authorized"] is True


def test_dast_options_forwarded(api):
    gate.main([
        "--api-url", "http://x", "--asset-id", "aaaa",
        "--dast-url", "http://localhost:3000",
        "--dast-profile", "baseline",
        "--dast-allow-private",
        "--dast-timeout", "120",
        "--requested-by", "ci-job-42",
    ])
    body = next(b for m, p, b in api.calls if m == "POST" and p == "/api/dast/scans")
    assert body["options"] == {"allow_private": True, "timeout_s": 120}
    assert body["requested_by"] == "ci-job-42"


def test_dast_failure_is_operational_error(api):
    api.dast_states = ["running", "failed"]
    api.dast_error = "zap sem relatorio"
    with pytest.raises(SystemExit) as e:
        gate.main([
            "--api-url", "http://x", "--asset-id", "aaaa",
            "--dast-url", "https://staging.example.com",
        ])
    assert e.value.code == 2


# ---------------------------------------------------------------------------
# Combos
# ---------------------------------------------------------------------------


def test_combined_sast_wait_and_dast(api):
    """--wait + --dast-url deve rodar os dois em sequencia e avaliar policy."""
    rc = gate.main([
        "--api-url", "http://x", "--asset-id", "aaaa",
        "--wait",
        "--dast-url", "https://staging.example.com",
    ])
    assert rc == 0
    posts = [p for m, p, _ in api.calls if m == "POST"]
    # SAST scan primeiro, DAST segundo, evaluate por ultimo
    assert posts.count("/api/dast/scans") == 1
    assert any(p.endswith("/scan") and not p.startswith("/api/dast") for p in posts)
    assert any("/policies/" in p and p.endswith("/evaluate") for p in posts)


def test_json_output_mode(api, capsys):
    gate.main([
        "--api-url", "http://x", "--asset-id", "aaaa",
        "--policy", "default", "--json",
    ])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["passed"] is True
    assert parsed["policy_name"] == "default"
