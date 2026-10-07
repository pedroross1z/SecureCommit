"""Semgrep — SAST. No Windows nativo, semgrep-core.exe nao existe: reporta unavailable."""
from __future__ import annotations

import json
import logging
import platform
from pathlib import Path

from app.config import settings
from app.core.collectors.base import Collector, resolve_bin, run_json_cmd
from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.collector.semgrep")

_BIN_CANDIDATES = ["semgrep"]


class SemgrepCollector:
    name = "semgrep"
    category = "sast"

    def is_available(self) -> bool:
        bin_path = resolve_bin("SEMGREP_BIN", _BIN_CANDIDATES)
        if not bin_path:
            return False
        # No Windows, o wheel do semgrep nao inclui semgrep-core.exe.
        if platform.system() == "Windows":
            logger.warning("semgrep no Windows nativo nao suporta semgrep-core; pulando")
            return False
        return True

    def run(self, repo_path: Path) -> list[RawFinding]:
        if not self.is_available():
            return []

        bin_path = resolve_bin("SEMGREP_BIN", _BIN_CANDIDATES) or "semgrep"
        cmd = [
            bin_path, "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            "--no-git-ignore",
            str(repo_path),
        ]
        stdout, stderr, rc = run_json_cmd(cmd, repo_path, settings.scanner_timeout_s)
        if rc == -1:
            logger.warning("semgrep timeout: %s", stderr)
            return []

        try:
            data = json.loads(stdout) if stdout.strip() else {"results": []}
        except json.JSONDecodeError as e:
            logger.warning("semgrep parse falhou: %s", e)
            return []

        findings: list[RawFinding] = []
        for r in data.get("results", []):
            extra = r.get("extra") or {}
            metadata = extra.get("metadata") or {}
            cwe_raw = metadata.get("cwe") or []
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw]
            findings.append(
                RawFinding(
                    source_tool=self.name,
                    category=self.category,
                    rule_id=r.get("check_id"),
                    title=(extra.get("message") or r.get("check_id") or "Semgrep finding")[:200],
                    description=extra.get("message"),
                    severity_raw=(extra.get("severity") or "").lower() or None,
                    cwe=[str(x) for x in cwe_raw if x],
                    file_path=r.get("path"),
                    line_start=(r.get("start") or {}).get("line"),
                    line_end=(r.get("end") or {}).get("line"),
                    snippet=(extra.get("lines") or "")[:1000] or None,
                    extra={
                        "owasp": metadata.get("owasp"),
                        "confidence": metadata.get("confidence"),
                    },
                )
            )
        logger.info("semgrep: %d findings", len(findings))
        return findings
