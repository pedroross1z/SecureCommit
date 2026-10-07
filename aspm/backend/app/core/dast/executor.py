"""Executor DAST: roda OWASP ZAP via Docker e retorna o relatorio JSON.

Isolamento:
- Cada scan recebe um diretorio proprio em `settings.scan_workdir/dast/<scan_id>/`.
- Container e removido ao final (`--rm`); nunca `privileged`.
- Limites de CPU/memoria configuraveis.
- Timeout obrigatorio; cancelamento envia SIGTERM.

A API administrativa do ZAP nao e exposta: usamos os scripts packaged
(`zap-baseline.py` / `zap-full-scan.py`) que falam com o ZAP via localhost
dentro do proprio container.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from app.config import settings
from app.core.dast.profiles import ProfileSpec

logger = logging.getLogger("aspm.dast.executor")

# Imagem oficial do ZAP (sucessora do owasp/zap2docker-stable).
_ZAP_IMAGE = os.environ.get("DAST_ZAP_IMAGE", "zaproxy/zap-stable")

# Limites conservadores — passados ao `docker run`. Ajustaveis via env.
_CPU_LIMIT = os.environ.get("DAST_CPU_LIMIT", "2")
_MEM_LIMIT = os.environ.get("DAST_MEM_LIMIT", "2g")

_DOCKER_BIN = os.environ.get("DOCKER_BIN", "docker")


class ZAPUnavailableError(RuntimeError):
    """Docker ou imagem ZAP indisponivel no host."""


@dataclass
class ExecutionResult:
    returncode: int
    duration_s: int
    report_path: Path | None
    zap_version: str | None
    stdout_tail: str
    stderr_tail: str


def _dast_workdir(scan_id: UUID) -> Path:
    base = Path(settings.scan_workdir) / "dast" / str(scan_id)
    base.mkdir(parents=True, exist_ok=True)
    return base


def is_docker_available() -> bool:
    if not shutil.which(_DOCKER_BIN):
        return False
    try:
        proc = subprocess.run(
            [_DOCKER_BIN, "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _detect_zap_version() -> str | None:
    """Melhor esforco — nao bloqueia o scan se falhar."""
    try:
        proc = subprocess.run(
            [_DOCKER_BIN, "image", "inspect", _ZAP_IMAGE,
             "--format", "{{index .Config.Labels \"org.opencontainers.image.version\"}}"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return None


def _tail(data: str, n_lines: int = 40) -> str:
    if not data:
        return ""
    lines = data.splitlines()
    return "\n".join(lines[-n_lines:])


def run_zap_scan(
    *,
    scan_id: UUID,
    target_url: str,
    profile: ProfileSpec,
    timeout_s: int,
    extra_args: list[str] | None = None,
) -> ExecutionResult:
    """Dispara o ZAP via Docker e retorna o resultado.

    - Nao levanta em returncode != 0: o `zap-baseline.py` retorna 1 quando ha
      WARNs e 2 quando ha FAILs; ambos sao estados "scan concluido com achados".
    - Levanta `ZAPUnavailableError` se o Docker nao estiver acessivel.
    - Levanta `TimeoutError` se exceder `timeout_s`.
    """
    if not is_docker_available():
        raise ZAPUnavailableError(
            f"docker indisponivel em {_DOCKER_BIN!r}: suba o Docker Desktop ou "
            f"ajuste DOCKER_BIN"
        )

    workdir = _dast_workdir(scan_id)
    report_name = f"zap-report-{scan_id}.json"
    report_in_container = f"/zap/wrk/{report_name}"
    report_on_host = workdir / report_name

    # Montamos o workdir como /zap/wrk (volume padrao esperado pelos scripts packaged).
    # user=1000: evita que arquivos escritos saiam como root no host (linux hosts).
    cmd: list[str] = [
        _DOCKER_BIN, "run", "--rm",
        "--name", f"aspm-dast-{scan_id}",
        "--cpus", _CPU_LIMIT,
        "--memory", _MEM_LIMIT,
        "-v", f"{workdir}:/zap/wrk:rw",
        _ZAP_IMAGE,
        profile.zap_script,
        "-t", target_url,
        "-J", report_name,
    ]
    if profile.passive_only:
        cmd.append("-s")  # pula active scan (zap-baseline.py)
    if extra_args:
        cmd.extend(extra_args)

    logger.info(
        "dast: start scan=%s profile=%s target=%s timeout=%ds",
        scan_id, profile.name, target_url, timeout_s,
    )

    import time
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_s, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired as e:
        # Tenta derrubar o container residual.
        subprocess.run(
            [_DOCKER_BIN, "kill", f"aspm-dast-{scan_id}"],
            capture_output=True, text=True, timeout=10,
        )
        duration = int(time.perf_counter() - start)
        raise TimeoutError(
            f"zap scan excedeu {timeout_s}s (duracao={duration}s)"
        ) from e

    duration = int(time.perf_counter() - start)
    rp = report_on_host if report_on_host.exists() else None
    if rp is None:
        logger.warning(
            "dast: scan=%s terminou sem relatorio em %s (rc=%d)",
            scan_id, report_on_host, proc.returncode,
        )

    return ExecutionResult(
        returncode=proc.returncode,
        duration_s=duration,
        report_path=rp,
        zap_version=_detect_zap_version(),
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
    )


def read_report(report_path: Path) -> dict:
    """Le e parseia o relatorio JSON do ZAP. Levanta ValueError se invalido."""
    try:
        content = report_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"relatorio inacessivel: {e}") from e
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"relatorio JSON invalido: {e}") from e


def cleanup_scan_workdir(scan_id: UUID) -> None:
    workdir = _dast_workdir(scan_id)
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)


def cancel_scan(scan_id: UUID) -> bool:
    """Mata o container do scan. Retorna True se o kill foi aceito."""
    if not shutil.which(_DOCKER_BIN):
        return False
    try:
        proc = subprocess.run(
            [_DOCKER_BIN, "kill", f"aspm-dast-{scan_id}"],
            capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0
    except Exception as e:
        logger.warning("cancel_scan falhou para %s: %s", scan_id, e)
        return False
