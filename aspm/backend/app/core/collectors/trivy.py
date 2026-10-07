"""Trivy — SCA (vuln), IaC (misconfig), license."""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from app.config import settings
from app.core.collectors.base import Collector, resolve_bin, run_json_cmd
from app.schemas.common import RawFinding

logger = logging.getLogger("aspm.collector.trivy")

_BIN_CANDIDATES = [
    "trivy",
    str(Path(__file__).resolve().parents[3] / "bin" / "trivy.exe"),
    str(Path(__file__).resolve().parents[3] / "bin" / "trivy"),
]


def _cwes_from(entry: dict) -> list[str]:
    ids = entry.get("CweIDs") or []
    return [str(x) for x in ids] if isinstance(ids, list) else []


class TrivyCollector:
    name = "trivy"
    category_map = {
        "vuln": "sca",
        "misconfig": "iac",
        "secret": "secret",
        "license": "license",
    }

    def __init__(self) -> None:
        self.category = "sca"  # categoria "padrao"; itens individuais setam a propria

    def is_available(self) -> bool:
        return resolve_bin("TRIVY_BIN", _BIN_CANDIDATES) is not None

    def run(self, repo_path: Path) -> list[RawFinding]:
        bin_path = resolve_bin("TRIVY_BIN", _BIN_CANDIDATES)
        if not bin_path:
            logger.warning("trivy nao encontrado; pulando")
            return []

        with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False, encoding="utf-8") as tf:
            report_path = tf.name

        env = os.environ.copy()
        # Silencia banners e desabilita telemetria
        env.setdefault("TRIVY_QUIET", "true")
        env.setdefault("TRIVY_DISABLE_VEX_NOTICE", "true")

        cmd = [
            bin_path, "fs",
            "--format", "json",
            "--scanners", "vuln,misconfig",
            "--output", report_path,
            "--exit-code", "0",
            str(repo_path),
        ]

        import subprocess
        logger.info("running trivy fs")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=settings.scanner_timeout_s, env=env,
                encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired:
            logger.warning("trivy timeout")
            return []

        if proc.returncode != 0:
            logger.warning("trivy rc=%d stderr=%s", proc.returncode, proc.stderr[:300])

        try:
            with open(report_path, encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("trivy parse falhou: %s", e)
            return []

        findings: list[RawFinding] = []
        for res in data.get("Results", []):
            target = res.get("Target")

            for v in res.get("Vulnerabilities", []) or []:
                findings.append(
                    RawFinding(
                        source_tool=self.name,
                        category="sca",
                        rule_id=v.get("VulnerabilityID"),
                        cve=v.get("VulnerabilityID"),
                        title=v.get("Title") or v.get("VulnerabilityID") or "Vulnerabilidade",
                        description=v.get("Description"),
                        severity_raw=(v.get("Severity") or "").lower() or None,
                        cwe=_cwes_from(v),
                        file_path=target,
                        package_name=v.get("PkgName"),
                        package_version=v.get("InstalledVersion"),
                        fixed_version=v.get("FixedVersion"),
                        extra={
                            "primary_url": v.get("PrimaryURL"),
                            "published": v.get("PublishedDate"),
                        },
                    )
                )

            for m in res.get("Misconfigurations", []) or []:
                loc = (m.get("CauseMetadata") or {})
                findings.append(
                    RawFinding(
                        source_tool=self.name,
                        category="iac",
                        rule_id=m.get("ID"),
                        title=m.get("Title") or m.get("ID") or "Misconfiguration",
                        description=m.get("Description") or m.get("Message"),
                        severity_raw=(m.get("Severity") or "").lower() or None,
                        cwe=[],
                        file_path=target,
                        line_start=loc.get("StartLine"),
                        line_end=loc.get("EndLine"),
                        snippet=(m.get("Resolution") or "")[:500] or None,
                        extra={
                            "type": m.get("Type"),
                            "namespace": m.get("Namespace"),
                        },
                    )
                )

        logger.info("trivy: %d findings", len(findings))
        return findings
