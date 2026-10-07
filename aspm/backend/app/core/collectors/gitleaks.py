"""Gitleaks — deteccao de secrets."""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from app.config import settings
from app.core.collectors.base import Collector, resolve_bin, run_json_cmd
from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.collector.gitleaks")

_BIN_CANDIDATES = [
    "gitleaks",
    str(Path(__file__).resolve().parents[3] / "bin" / "gitleaks.exe"),
    str(Path(__file__).resolve().parents[3] / "bin" / "gitleaks"),
]


def _redact_secret(raw: str) -> str:
    if not raw:
        return ""
    if len(raw) <= 8:
        return "*" * len(raw)
    return raw[:4] + "****" + raw[-2:]


class GitleaksCollector:
    name = "gitleaks"
    category = "secret"

    def is_available(self) -> bool:
        return resolve_bin("GITLEAKS_BIN", _BIN_CANDIDATES) is not None

    def run(self, repo_path: Path) -> list[RawFinding]:
        bin_path = resolve_bin("GITLEAKS_BIN", _BIN_CANDIDATES)
        if not bin_path:
            logger.warning("gitleaks nao encontrado; pulando")
            return []

        with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False, encoding="utf-8") as tf:
            report_path = tf.name

        cmd = [
            bin_path,
            "detect",
            "--source", str(repo_path),
            "--report-format", "json",
            "--report-path", report_path,
            "--no-git",
            "--exit-code", "0",
        ]
        stdout, stderr, rc = run_json_cmd(cmd, repo_path, settings.scanner_timeout_s)
        if rc == -1:
            logger.warning("gitleaks timeout/error: %s", stderr)
            return []

        try:
            with open(report_path, encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("gitleaks parse falhou: %s", e)
            return []

        findings: list[RawFinding] = []
        for item in data:
            secret_raw = item.get("Secret") or ""
            findings.append(
                RawFinding(
                    source_tool=self.name,
                    category=self.category,
                    rule_id=item.get("RuleID"),
                    title=item.get("Description") or f"Secret detectado ({item.get('RuleID', '?')})",
                    description=(
                        f"Match: {_redact_secret(item.get('Match') or secret_raw)}\n"
                        f"Regra: {item.get('RuleID')}"
                    ),
                    severity_raw="high",
                    file_path=item.get("File"),
                    line_start=item.get("StartLine"),
                    line_end=item.get("EndLine"),
                    snippet=_redact_secret(item.get("Match") or ""),
                    extra={
                        "entropy": item.get("Entropy"),
                        "tags": item.get("Tags"),
                    },
                )
            )
        logger.info("gitleaks: %d findings", len(findings))
        return findings
