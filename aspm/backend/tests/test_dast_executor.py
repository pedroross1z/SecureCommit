"""Executor DAST: valida comando `docker run` montado + parsing de resultado.

Mocka `subprocess.run` para capturar o comando exato e evitar depender de
Docker/ZAP no CI. Cobre: perfil passive adiciona `-s`, limites de CPU/mem,
workdir isolado por scan_id, read_report, cancel, timeout propagation.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.dast import executor as zap_exec
from app.core.dast.profiles import get_profile


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr="") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def _workdir(tmp_path, monkeypatch):
    """Isola `settings.scan_workdir` em tmp_path para nao poluir o disco real."""
    monkeypatch.setattr(zap_exec.settings, "scan_workdir", str(tmp_path))
    return tmp_path


def _write_report(workdir: Path, scan_id: uuid.UUID, report=None):
    (workdir / "dast" / str(scan_id)).mkdir(parents=True, exist_ok=True)
    report_file = workdir / "dast" / str(scan_id) / f"zap-report-{scan_id}.json"
    report_file.write_text(
        json.dumps(report or {"@version": "2.14", "site": []}), encoding="utf-8"
    )
    return report_file


# ---------------------------------------------------------------------------
# Comando docker run
# ---------------------------------------------------------------------------


def test_baseline_profile_invokes_zap_baseline_py(_workdir, monkeypatch):
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: True)
    captured: dict = {"cmds": []}

    def _fake_run(cmd, **kw):
        captured["cmds"].append(cmd)
        # Primeira chamada = scan (tem --name); segunda = inspect (sem --name)
        if "--name" in cmd:
            scan_id = uuid.UUID(cmd[cmd.index("--name") + 1].replace("aspm-dast-", ""))
            _write_report(_workdir, scan_id)
            return _FakeCompleted(returncode=0, stdout="ok", stderr="")
        return _FakeCompleted(returncode=0, stdout="2.14.0", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    scan_id = uuid.uuid4()
    result = zap_exec.run_zap_scan(
        scan_id=scan_id,
        target_url="https://alvo.example",
        profile=get_profile("baseline"),
        timeout_s=60,
    )
    scan_cmd = next(c for c in captured["cmds"] if "--name" in c)
    assert "docker" in scan_cmd[0] or scan_cmd[0].endswith("docker")
    assert "run" in scan_cmd and "--rm" in scan_cmd
    assert "zap-baseline.py" in scan_cmd
    assert "-t" in scan_cmd and "https://alvo.example" in scan_cmd
    # Nao envia flag `-s` em baseline (so em passive)
    assert "-s" not in scan_cmd
    # Nao usa --privileged
    assert "--privileged" not in scan_cmd
    # Isola CPU e memoria
    assert "--cpus" in scan_cmd and "--memory" in scan_cmd
    # Volume aponta para o workdir do scan
    volume_arg = scan_cmd[scan_cmd.index("-v") + 1]
    assert str(scan_id) in volume_arg
    assert ":/zap/wrk:rw" in volume_arg

    assert result.returncode == 0
    assert result.report_path is not None


def _make_run_capture(workdir: Path):
    """Factory de _fake_run que captura o cmd de scan e escreve relatorio."""
    cmds: list[list[str]] = []

    def _fake(cmd, **kw):
        cmds.append(cmd)
        if "--name" in cmd:
            scan_id = uuid.UUID(cmd[cmd.index("--name") + 1].replace("aspm-dast-", ""))
            _write_report(workdir, scan_id)
            return _FakeCompleted(returncode=0)
        return _FakeCompleted(returncode=0, stdout="2.14.0")

    return _fake, cmds


def _scan_cmd(cmds: list[list[str]]) -> list[str]:
    return next(c for c in cmds if "--name" in c)


def test_passive_profile_adds_s_flag(_workdir, monkeypatch):
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: True)
    fake, cmds = _make_run_capture(_workdir)
    monkeypatch.setattr(subprocess, "run", fake)
    zap_exec.run_zap_scan(
        scan_id=uuid.uuid4(),
        target_url="https://alvo.example",
        profile=get_profile("passive"),
        timeout_s=60,
    )
    assert "-s" in _scan_cmd(cmds)


def test_active_profile_invokes_zap_full_scan(_workdir, monkeypatch):
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: True)
    fake, cmds = _make_run_capture(_workdir)
    monkeypatch.setattr(subprocess, "run", fake)
    zap_exec.run_zap_scan(
        scan_id=uuid.uuid4(),
        target_url="https://alvo.example",
        profile=get_profile("active"),
        timeout_s=60,
    )
    scan_cmd = _scan_cmd(cmds)
    assert "zap-full-scan.py" in scan_cmd
    assert "-s" not in scan_cmd  # active quer o scanner ativo


def test_extra_args_appended(_workdir, monkeypatch):
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: True)
    fake, cmds = _make_run_capture(_workdir)
    monkeypatch.setattr(subprocess, "run", fake)
    zap_exec.run_zap_scan(
        scan_id=uuid.uuid4(),
        target_url="https://alvo.example",
        profile=get_profile("baseline"),
        timeout_s=60,
        extra_args=["-d", "-m", "5"],
    )
    assert _scan_cmd(cmds)[-3:] == ["-d", "-m", "5"]


# ---------------------------------------------------------------------------
# Returncode e report
# ---------------------------------------------------------------------------


def test_nonzero_returncode_is_not_error(_workdir, monkeypatch):
    """zap-baseline.py retorna 1 quando ha WARNs e 2 em FAILs — ambos sao
    scan concluido com achados, nao erro operacional."""
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: True)

    def _fake_run(cmd, **kw):
        scan_id = uuid.UUID(cmd[cmd.index("--name") + 1].replace("aspm-dast-", ""))
        _write_report(_workdir, scan_id)
        return _FakeCompleted(returncode=2, stderr="2 FAIL(s)")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = zap_exec.run_zap_scan(
        scan_id=uuid.uuid4(),
        target_url="https://alvo.example",
        profile=get_profile("baseline"),
        timeout_s=60,
    )
    assert result.returncode == 2
    assert result.report_path is not None  # scan concluiu


def test_missing_report_returns_none_report_path(_workdir, monkeypatch):
    """Container terminou mas nao escreveu relatorio: report_path=None."""
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: True)

    def _fake_run(cmd, **kw):
        return _FakeCompleted(returncode=1, stderr="fail")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = zap_exec.run_zap_scan(
        scan_id=uuid.uuid4(),
        target_url="https://alvo.example",
        profile=get_profile("baseline"),
        timeout_s=60,
    )
    assert result.report_path is None


# ---------------------------------------------------------------------------
# Falhas estruturais
# ---------------------------------------------------------------------------


def test_zap_unavailable_when_docker_absent(_workdir, monkeypatch):
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: False)
    with pytest.raises(zap_exec.ZAPUnavailableError):
        zap_exec.run_zap_scan(
            scan_id=uuid.uuid4(),
            target_url="https://alvo.example",
            profile=get_profile("baseline"),
            timeout_s=60,
        )


def test_timeout_raises_timeouterror_and_kills_container(_workdir, monkeypatch):
    monkeypatch.setattr(zap_exec, "is_docker_available", lambda: True)
    killed: dict = {"n": 0, "cmd": None}

    def _fake_run(cmd, **kw):
        if cmd[0:2] == [zap_exec._DOCKER_BIN, "kill"] or cmd[1] == "kill":
            killed["n"] += 1
            killed["cmd"] = cmd
            return _FakeCompleted(returncode=0)
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kw.get("timeout", 60))

    monkeypatch.setattr(subprocess, "run", _fake_run)
    scan_id = uuid.uuid4()
    with pytest.raises(TimeoutError, match="excedeu"):
        zap_exec.run_zap_scan(
            scan_id=scan_id,
            target_url="https://alvo.example",
            profile=get_profile("baseline"),
            timeout_s=1,
        )
    assert killed["n"] == 1
    # Comando de kill referencia o container do scan
    assert f"aspm-dast-{scan_id}" in killed["cmd"]


# ---------------------------------------------------------------------------
# read_report
# ---------------------------------------------------------------------------


def test_read_report_parses_valid_json(tmp_path):
    report = tmp_path / "r.json"
    data = {"@version": "2.14", "site": []}
    report.write_text(json.dumps(data), encoding="utf-8")
    parsed = zap_exec.read_report(report)
    assert parsed == data


def test_read_report_raises_valueerror_on_invalid_json(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError):
        zap_exec.read_report(report)


def test_read_report_raises_valueerror_on_missing_file(tmp_path):
    with pytest.raises(ValueError):
        zap_exec.read_report(tmp_path / "missing.json")


# ---------------------------------------------------------------------------
# cancel_scan
# ---------------------------------------------------------------------------


def test_cancel_scan_invokes_docker_kill(_workdir, monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(zap_exec.shutil, "which", lambda _: "/usr/bin/docker")

    def _fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _FakeCompleted(returncode=0)

    monkeypatch.setattr(subprocess, "run", _fake_run)
    scan_id = uuid.uuid4()
    assert zap_exec.cancel_scan(scan_id) is True
    assert captured["cmd"][1] == "kill"
    assert f"aspm-dast-{scan_id}" in captured["cmd"]


def test_cancel_scan_returns_false_when_docker_missing(monkeypatch):
    monkeypatch.setattr(zap_exec.shutil, "which", lambda _: None)
    assert zap_exec.cancel_scan(uuid.uuid4()) is False
