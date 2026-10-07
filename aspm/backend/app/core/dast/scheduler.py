"""Scheduler asyncio: polla monitores DAST em cadencia.

Loop simples: a cada `TICK_S` segundos, busca monitores com `status='running'`
e `next_poll_at <= now`, e dispara `poll_monitor` em thread executor para
nao bloquear o event loop.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.dast.monitor import poll_monitor
from app.db import SessionLocal
from app.models import DastMonitor

logger = logging.getLogger("aspm.dast.scheduler")

TICK_S = 5.0  # frequencia de verificacao (nao de poll)


async def _tick() -> None:
    """Processa os monitores prontos para poll."""
    loop = asyncio.get_running_loop()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        rows = db.scalars(
            select(DastMonitor).where(
                DastMonitor.status == "running",
                DastMonitor.next_poll_at.is_not(None),
                DastMonitor.next_poll_at <= now,
            )
        ).all()
        monitor_ids = [m.id for m in rows]
    finally:
        db.close()

    for mid in monitor_ids:
        # poll_monitor eh sincrono (abre session, chama httpx, grava DB).
        # Rodar em executor evita bloquear o event loop.
        try:
            await loop.run_in_executor(None, poll_monitor, mid)
        except Exception:
            logger.exception("scheduler: poll_monitor %s falhou", mid)


async def scheduler_loop(stop_event: asyncio.Event) -> None:
    logger.info("dast scheduler: iniciado (tick=%.1fs)", TICK_S)
    while not stop_event.is_set():
        try:
            await _tick()
        except Exception:
            logger.exception("scheduler tick falhou")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=TICK_S)
        except asyncio.TimeoutError:
            pass
    logger.info("dast scheduler: parado")
