import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api import assets as assets_api
from app.api import clusters as clusters_api
from app.api import dast as dast_api
from app.api import findings as findings_api
from app.api import policies as policies_api
from app.api import remediations as remediations_api
from app.api import scans as scans_api
from app.config import settings
from app.core.dast.scheduler import scheduler_loop
from app.db import engine, init_db

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("aspm")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("db initialized (url=%s)", settings.database_url)
    stop_event = asyncio.Event()
    scheduler_task = asyncio.create_task(scheduler_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        try:
            await asyncio.wait_for(scheduler_task, timeout=10)
        except asyncio.TimeoutError:
            scheduler_task.cancel()


app = FastAPI(title="ASPM MVP", version="0.1.0", lifespan=lifespan)
app.include_router(assets_api.router)
app.include_router(scans_api.router)
app.include_router(findings_api.router)
app.include_router(clusters_api.router)
app.include_router(remediations_api.router)
app.include_router(policies_api.router)
app.include_router(dast_api.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    db_ok = False
    db_error: str | None = None
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_error = str(e)
        logger.exception("db healthcheck failed")

    dialect = engine.dialect.name
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "aspm-backend",
        "version": app.version,
        "db": {"ok": db_ok, "dialect": dialect, "error": db_error},
    }


@app.get("/")
def root() -> dict:
    return {"service": "aspm-backend", "docs": "/docs", "health": "/health"}
