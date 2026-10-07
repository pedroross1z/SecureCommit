"""Pilar 1 — Descoberta: clone, deteccao de linguagens, IA de contexto."""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.ai.client import AIUnavailableError, get_ai
from app.models import Asset
from app.schemas.ai import DiscoveryContext

logger = logging.getLogger("aspm.discovery")

_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".c": "c", ".cpp": "cpp", ".h": "c",
    ".swift": "swift", ".m": "objc",
    ".sh": "shell", ".yaml": "yaml", ".yml": "yaml",
    ".tf": "terraform", ".hcl": "terraform",
    ".sql": "sql", ".html": "html", ".css": "css",
}

_MANIFEST_FILES = {
    "requirements.txt", "pyproject.toml", "Pipfile",
    "package.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
    "Gemfile", "composer.json",
}

_IAC_PATTERNS = (".tf", ".tfvars")
_IAC_FILES = {"docker-compose.yml", "docker-compose.yaml"}

_AUTH_LIB_PATTERNS = [
    r"passport", r"django\.contrib\.auth", r"flask[_-]login", r"flask[_-]jwt",
    r"pyjwt", r"jsonwebtoken", r"next-auth", r"clerk", r"auth0",
    r"spring-security", r"devise", r"omniauth",
]
_AUTH_RE = re.compile("|".join(_AUTH_LIB_PATTERNS), re.IGNORECASE)

_ROUTE_HINT_RE = re.compile(
    r"@app\.(get|post|put|delete|patch)|@router\.(get|post|put|delete|patch)|"
    r"app\.(get|post|put|delete|patch)\s*\(|"
    r"router\.(get|post|put|delete|patch)\s*\(|"
    r"@RequestMapping|@GetMapping|@PostMapping|"
    r"http\.HandleFunc|mux\.HandleFunc",
    re.IGNORECASE,
)


@dataclass
class DiscoveryResult:
    repo_path: Path
    commit_sha: str | None
    name: str
    default_branch: str
    languages: dict[str, float]
    manifests: list[str]
    iac_files: list[str]
    dockerfile: bool
    auth_libs: list[str]
    routes_count: int
    readme_excerpt: str
    context: DiscoveryContext | None
    context_source: str  # 'ai' | 'unknown'


def _rmtree_robust(path: Path) -> None:
    """rmtree que lida com arquivos read-only comuns em .git no Windows."""
    import os
    import stat

    def _on_error(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if not path.exists():
        return
    try:
        shutil.rmtree(path, onexc=_on_error)  # type: ignore[call-arg]
    except TypeError:
        shutil.rmtree(path, onerror=lambda f, p, e: _on_error(f, p, e))


def clone_repo(repo_url: str, dest: Path) -> tuple[Path, str | None, str]:
    """git clone --depth 1. Retorna (path, commit_sha, default_branch)."""
    _rmtree_robust(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info("cloning %s into %s", repo_url, dest)
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(dest)],
        check=True, capture_output=True, text=True, timeout=300,
    )
    sha = None
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(dest), text=True, timeout=30
        ).strip()
    except Exception:
        pass
    branch = "main"
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(dest), text=True, timeout=30
        ).strip() or "main"
    except Exception:
        pass
    return dest, sha, branch


def _detect_languages(repo: Path) -> dict[str, float]:
    counts: dict[str, int] = {}
    total = 0
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        lang = _LANG_BY_EXT.get(p.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
            total += 1
    if total == 0:
        return {}
    return {k: round(v / total, 3) for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:6]}


def _find_manifests(repo: Path) -> list[str]:
    found: list[str] = []
    for p in repo.rglob("*"):
        if p.is_file() and p.name in _MANIFEST_FILES and ".git" not in p.parts:
            rel = str(p.relative_to(repo)).replace("\\", "/")
            found.append(rel)
    return sorted(set(found))[:30]


def _find_iac(repo: Path) -> tuple[list[str], bool]:
    iac: list[str] = []
    dockerfile = False
    for p in repo.rglob("*"):
        if not p.is_file() or ".git" in p.parts:
            continue
        rel = str(p.relative_to(repo)).replace("\\", "/")
        if p.suffix in _IAC_PATTERNS or p.name in _IAC_FILES:
            iac.append(rel)
        if p.name == "Dockerfile" or p.name.startswith("Dockerfile."):
            dockerfile = True
    return sorted(set(iac))[:20], dockerfile


def _detect_auth_and_routes(repo: Path, manifest_paths: list[str]) -> tuple[list[str], int]:
    auth: set[str] = set()
    for m in manifest_paths:
        try:
            content = (repo / m).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _AUTH_RE.findall(content):
            auth.add(match if isinstance(match, str) else match[0])

    routes = 0
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for p in repo.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb"}:
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _ROUTE_HINT_RE.search(content):
            routes += 1
        # tambem varre por libs de auth em codigo
        for match in _AUTH_RE.findall(content):
            auth.add(match if isinstance(match, str) else match[0])
        if routes > 200:
            break
    return sorted(auth), routes


def _read_readme(repo: Path, max_chars: int = 3000) -> str:
    for name in ("README.md", "README.rst", "README.txt", "README"):
        p = repo / name
        if p.exists():
            try:
                return p.read_text(encoding="utf-8", errors="ignore")[:max_chars]
            except OSError:
                pass
    return ""


def perform_discovery(repo_url: str, workdir: Path, name_hint: str | None = None) -> DiscoveryResult:
    """Executa toda a fase de discovery (sem persistir no banco)."""
    repo_path, sha, branch = clone_repo(repo_url, workdir)

    name = name_hint or repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
    languages = _detect_languages(repo_path)
    manifests = _find_manifests(repo_path)
    iac_files, dockerfile = _find_iac(repo_path)
    auth_libs, routes_count = _detect_auth_and_routes(repo_path, manifests)
    readme = _read_readme(repo_path)

    ctx: DiscoveryContext | None = None
    ctx_source = "unknown"
    ai = get_ai()
    if ai.enabled:
        try:
            parsed, _telemetry = ai.call_structured(
                prompt_name="discovery",
                prompt_vars={
                    "name": name,
                    "default_branch": branch,
                    "languages_json": json.dumps(languages),
                    "manifests": ", ".join(manifests[:10]) or "nenhum",
                    "iac_files": ", ".join(iac_files[:10]) or "nenhum",
                    "dockerfile_present": "sim" if dockerfile else "nao",
                    "auth_libs": ", ".join(auth_libs) or "nenhuma detectada",
                    "routes_count": routes_count,
                    "readme_excerpt": readme or "(sem README)",
                },
                response_model=DiscoveryContext,
                model="claude-haiku-4-5",
                max_tokens=512,
            )
            ctx = parsed
            ctx_source = "ai"
        except AIUnavailableError as e:
            logger.warning("discovery AI indisponivel: %s", e)
        except Exception as e:
            # Spec: nunca travar o pipeline por falha de IA. Degrada para unknown.
            logger.warning("discovery AI falhou inesperadamente: %s", e)
    else:
        logger.info("ANTHROPIC_API_KEY nao configurada; discovery sem IA")

    return DiscoveryResult(
        repo_path=repo_path,
        commit_sha=sha,
        name=name,
        default_branch=branch,
        languages=languages,
        manifests=manifests,
        iac_files=iac_files,
        dockerfile=dockerfile,
        auth_libs=auth_libs,
        routes_count=routes_count,
        readme_excerpt=readme,
        context=ctx,
        context_source=ctx_source,
    )


def apply_discovery_to_asset(db: Session, asset: Asset, result: DiscoveryResult) -> None:
    """Persiste dados de discovery no asset."""
    asset.name = result.name
    asset.default_branch = result.default_branch
    asset.languages = result.languages
    asset.frameworks = {"manifests": result.manifests[:15], "iac": result.iac_files[:15]}
    asset.criticality_source = result.context_source
    if result.context is not None:
        asset.criticality = result.context.criticality
        asset.internet_facing = result.context.internet_facing
        asset.handles_pii = result.context.handles_pii
        asset.has_auth = result.context.has_auth
        asset.ai_rationale = result.context.rationale
    db.add(asset)
    db.commit()
    db.refresh(asset)
