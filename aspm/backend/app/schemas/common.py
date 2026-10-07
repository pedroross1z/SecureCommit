from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RawFinding:
    """Finding cru saido de um scanner, antes da normalizacao."""

    source_tool: str            # semgrep|trivy|gitleaks
    category: str               # sast|sca|secret|iac|container
    title: str
    rule_id: str | None = None
    description: str | None = None
    severity_raw: str | None = None
    cwe: list[str] = field(default_factory=list)
    cve: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
