import logging
from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

logger = logging.getLogger("aspm.db")

_is_sqlite = settings.database_url.startswith("sqlite")
engine_kwargs: dict = {"pool_pre_ping": True, "future": True}
if _is_sqlite:
    # SQLite exige check_same_thread=False para uso com FastAPI (threads).
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Cria tabelas via SQLAlchemy quando nao ha Postgres+migrations disponivel.

    Em Postgres/Docker, as migrations em `backend/migrations/*.sql` sao aplicadas
    pelo entrypoint. Aqui, para dev com SQLite (ou primeiro boot), garantimos o
    schema pelos modelos.
    """
    # Import tardio para registrar os models no metadata do Base.
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    if _is_sqlite:
        _sqlite_add_missing_columns()


# Colunas acrescidas em migrations posteriores que precisam entrar numa base
# SQLite ja existente. (sqlite nao suporta IF NOT EXISTS para colunas < 3.35.)
_SQLITE_PATCH_COLUMNS: dict[str, dict[str, str]] = {
    "findings": {
        "url": "TEXT",
        "http_method": "TEXT",
        "parameter": "TEXT",
        "evidence": "TEXT",
        "solution": "TEXT",
        "dast_scan_id": "CHAR(36)",
        "dast_monitor_id": "CHAR(36)",
    },
}


def _sqlite_add_missing_columns() -> None:
    """Patcha SQLite para colunas adicionadas em migrations novas."""
    with engine.begin() as conn:
        for table, cols in _SQLITE_PATCH_COLUMNS.items():
            try:
                rows = conn.execute(text(f"PRAGMA table_info({table})")).all()
            except Exception:
                continue
            existing = {r[1] for r in rows}
            for col, col_type in cols.items():
                if col in existing:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
                    logger.info("sqlite: added %s.%s", table, col)
                except Exception as e:
                    logger.warning("sqlite: failed to add %s.%s: %s", table, col, e)
