"""Interface comum para scanners."""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.collector")


@dataclass
class CollectorResult:
    findings: list[RawFinding]
    duration_s: float
    ok: bool
    error: str | None = None


class Collector(Protocol):
    name: str
    category: str

    def is_available(self) -> bool: ...
    def run(self, repo_path: Path) -> list[RawFinding]: ...


def resolve_bin(env_var_name: str, candidates: list[str]) -> str | None:
    """Localiza um binario: primeiro por PATH, depois em candidates absolutos."""
    import os

    override = os.environ.get(env_var_name)
    if override and Path(override).exists():
        return override
    for c in candidates:
        p = shutil.which(c)
        if p:
            return p
        if Path(c).exists():
            return c
    return None


def run_json_cmd(cmd: list[str], cwd: Path, timeout_s: int) -> tuple[str, str, int]:
    """Executa comando e retorna (stdout, stderr, returncode). Nunca levanta em codigo != 0."""
    logger.info("running: %s (cwd=%s)", " ".join(cmd[:4]), cwd)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            encoding="utf-8",
            errors="replace",
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as e:
        return "", f"timeout after {timeout_s}s: {e}", -1
