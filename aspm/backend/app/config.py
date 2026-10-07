from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Dev local usa SQLite em ./aspm.db. Producao/Docker sobrescreve com Postgres.
    database_url: str = f"sqlite:///{_REPO_ROOT / 'aspm.db'}"
    anthropic_api_key: str = ""
    log_level: str = "INFO"
    scan_workdir: str = str(_REPO_ROOT / "scan_workdir")
    policies_dir: str = str(_REPO_ROOT / "policies")
    scanner_timeout_s: int = 300
    ai_max_concurrency: int = 5


settings = Settings()
