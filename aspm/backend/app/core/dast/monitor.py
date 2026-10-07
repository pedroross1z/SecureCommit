"""Monitor DAST contínuo: ZAP daemon persistente + polling via ZAP API.

Diferente de `service.py` (one-shot scan), aqui o ZAP fica rodando como
daemon. O backend polla a API ZAP periodicamente (`poll_interval_s`),
normaliza alerts novos e upserta como findings DAST.

Fluxo:
1. `start_monitor` sobe container ZAP daemon em porta dinamica, injeta
   api_key gerado, dispara spider inicial contra o alvo.
2. Scheduler asyncio (em `scheduler.py`) chama `poll_monitor(monitor_id)`
   quando `next_poll_at <= now`.
3. `poll_monitor` chama ZAP API /JSON/core/view/alerts, normaliza e upsert.
   Agenda proximo poll.
4. `stop_monitor` mata o container e marca stopped.
"""
from __future__ import annotations

import logging
import os
import random
import secrets
import shutil
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dast.api_normalizer import normalize_zap_alerts, summarize_alerts
from app.core.dast.correlator import correlate_dast_sast
from app.core.dast.ssrf import SSRFError, validate_target_url
from app.core.normalizer import upsert_findings
from app.db import SessionLocal
from app.models import Asset, DastMonitor, Scan

logger = logging.getLogger("aspm.dast.monitor")

_ZAP_IMAGE = os.environ.get("DAST_ZAP_IMAGE", "zaproxy/zap-stable")
_CPU_LIMIT = os.environ.get("DAST_CPU_LIMIT", "2")
_MEM_LIMIT = os.environ.get("DAST_MEM_LIMIT", "2g")
_DOCKER_BIN = os.environ.get("DOCKER_BIN", "docker")
_PORT_MIN = 18080
_PORT_MAX = 18200


# ---------------------------------------------------------------------------
# Infra: porta livre, docker, zap api
# ---------------------------------------------------------------------------


class ZAPUnavailableError(RuntimeError):
    pass


def _pick_free_port() -> int:
    """Encontra uma porta TCP livre no range reservado para monitors."""
    tried = set()
    for _ in range(50):
        port = random.randint(_PORT_MIN, _PORT_MAX)
        if port in tried:
            continue
        tried.add(port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise ZAPUnavailableError("sem portas livres no range do monitor")


def _is_docker_available() -> bool:
    if not shutil.which(_DOCKER_BIN):
        return False
    try:
        proc = subprocess.run(
            [_DOCKER_BIN, "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _container_name(monitor_id: UUID) -> str:
    return f"aspm-zap-monitor-{monitor_id}"


def _zap_base_url(port: int) -> str:
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# ZAP API client
# ---------------------------------------------------------------------------


class ZAPClient:
    """Cliente HTTP minimo pra ZAP REST API."""

    def __init__(self, base_url: str, api_key: str, timeout_s: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_s

    def _get(self, path: str, **params) -> dict:
        params["apikey"] = self._api_key
        with httpx.Client(timeout=self._timeout) as client:
            r = client.get(f"{self._base}{path}", params=params)
        r.raise_for_status()
        return r.json()

    def version(self) -> str:
        return self._get("/JSON/core/view/version/").get("version", "?")

    def spider_scan(self, url: str, max_children: int = 20) -> str:
        """Dispara spider. Retorna scan_id."""
        res = self._get(
            "/JSON/spider/action/scan/",
            url=url, maxChildren=max_children, recurse="true",
            subtreeOnly="false",
        )
        return str(res.get("scan", ""))

    def spider_status(self, scan_id: str) -> int:
        res = self._get("/JSON/spider/view/status/", scanId=scan_id)
        try:
            return int(res.get("status", "0"))
        except ValueError:
            return 0

    def alerts(self, base_url: str | None = None) -> list[dict]:
        """Lista alerts acumulados. baseurl filtra por raiz."""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        res = self._get("/JSON/core/view/alerts/", **params)
        return res.get("alerts", []) or []

    def shutdown(self) -> None:
        try:
            self._get("/JSON/core/action/shutdown/")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Start / stop
# ---------------------------------------------------------------------------


def _run_container_detached(name: str, port: int, api_key: str) -> None:
    cmd = [
        _DOCKER_BIN, "run", "--rm", "-d",
        "--name", name,
        "--cpus", _CPU_LIMIT,
        "--memory", _MEM_LIMIT,
        "-p", f"127.0.0.1:{port}:8090",
        _ZAP_IMAGE,
        "zap.sh", "-daemon",
        "-host", "0.0.0.0", "-port", "8090",
        "-config", f"api.key={api_key}",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
    ]
    logger.info("monitor: docker run %s on port %d", name, port)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise ZAPUnavailableError(
            f"docker run falhou (rc={proc.returncode}): {proc.stderr[:300]}"
        )


def _wait_for_zap_api(port: int, api_key: str, timeout_s: int = 90) -> str:
    """Aguarda ZAP API responder. Retorna versao."""
    client = ZAPClient(_zap_base_url(port), api_key, timeout_s=3.0)
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return client.version()
        except Exception as e:
            last_err = e
            time.sleep(2)
    raise ZAPUnavailableError(f"ZAP API nao respondeu em {timeout_s}s: {last_err}")


def _kill_container(name: str) -> None:
    try:
        subprocess.run(
            [_DOCKER_BIN, "kill", name],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        logger.warning("falha ao matar container %s: %s", name, e)


def start_monitor_task(monitor_id: str) -> None:
    """BackgroundTask: sobe o ZAP daemon e dispara spider inicial."""
    mid = UUID(monitor_id)
    db: Session = SessionLocal()
    try:
        monitor = db.get(DastMonitor, mid)
        if monitor is None:
            logger.warning("monitor %s nao encontrado", monitor_id)
            return

        if not _is_docker_available():
            monitor.status = "failed"
            monitor.last_error = "docker indisponivel"
            db.commit()
            return

        try:
            port = _pick_free_port()
            api_key = secrets.token_urlsafe(16)
            container = _container_name(mid)
            _run_container_detached(container, port, api_key)
        except ZAPUnavailableError as e:
            monitor.status = "failed"
            monitor.last_error = str(e)
            db.commit()
            return

        monitor.zap_container = container
        monitor.zap_port = port
        monitor.zap_api_key = api_key
        monitor.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            version = _wait_for_zap_api(port, api_key, timeout_s=120)
        except ZAPUnavailableError as e:
            monitor.status = "failed"
            monitor.last_error = str(e)
            _kill_container(container)
            db.commit()
            return

        # Spider inicial
        client = ZAPClient(_zap_base_url(port), api_key)
        try:
            client.spider_scan(monitor.target_url, max_children=20)
        except Exception as e:
            logger.warning("spider inicial falhou: %s", e)

        monitor.status = "running"
        monitor.next_poll_at = datetime.now(timezone.utc) + timedelta(
            seconds=monitor.poll_interval_s
        )
        db.commit()
        logger.info(
            "monitor %s running on port %d (zap %s)",
            monitor_id, port, version,
        )
    finally:
        db.close()


def stop_monitor(db: Session, monitor_id: UUID) -> DastMonitor:
    monitor = db.get(DastMonitor, monitor_id)
    if monitor is None:
        raise ValueError("monitor nao encontrado")
    if monitor.status == "stopped":
        return monitor
    if monitor.zap_container:
        _kill_container(monitor.zap_container)
    monitor.status = "stopped"
    monitor.stopped_at = datetime.now(timezone.utc)
    monitor.next_poll_at = None
    db.commit()
    db.refresh(monitor)
    return monitor


def respider_monitor(db: Session, monitor_id: UUID) -> DastMonitor:
    """Re-dispara spider pra descobrir rotas novas."""
    monitor = db.get(DastMonitor, monitor_id)
    if monitor is None:
        raise ValueError("monitor nao encontrado")
    if monitor.status != "running":
        raise ValueError(f"monitor nao esta running (status={monitor.status})")
    if not monitor.zap_port or not monitor.zap_api_key:
        raise ValueError("monitor sem ZAP ativo")
    client = ZAPClient(_zap_base_url(monitor.zap_port), monitor.zap_api_key)
    try:
        client.spider_scan(monitor.target_url, max_children=20)
    except Exception as e:
        raise ValueError(f"spider falhou: {e}") from e
    return monitor


# ---------------------------------------------------------------------------
# Poll — chamado pelo scheduler
# ---------------------------------------------------------------------------


def poll_monitor(monitor_id: UUID) -> None:
    """Puxa alerts da ZAP API, normaliza e upserta como findings."""
    db: Session = SessionLocal()
    try:
        monitor = db.get(DastMonitor, monitor_id)
        if monitor is None:
            return
        if monitor.status != "running" or not monitor.zap_port or not monitor.zap_api_key:
            return

        client = ZAPClient(
            _zap_base_url(monitor.zap_port), monitor.zap_api_key, timeout_s=15.0
        )
        try:
            alerts = client.alerts(base_url=monitor.target_url)
        except Exception as e:
            monitor.last_error = f"poll falhou: {type(e).__name__}: {e}"[:500]
            monitor.last_poll_at = datetime.now(timezone.utc)
            monitor.next_poll_at = datetime.now(timezone.utc) + timedelta(
                seconds=monitor.poll_interval_s
            )
            db.commit()
            logger.warning("monitor %s poll falhou: %s", monitor_id, e)
            return

        asset = db.get(Asset, monitor.asset_id)
        if asset is None:
            return

        raws = normalize_zap_alerts(alerts)
        summary = summarize_alerts(alerts)

        # Host Scan dummy — reusa o padrao dos scans one-shot pra satisfazer FK.
        host_scan = Scan(
            asset_id=asset.id,
            status="done",
            started_at=monitor.last_poll_at or datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            tool_stats={
                "source": "dast-monitor",
                "dast_monitor_id": str(monitor_id),
                "poll": monitor.polls_total + 1,
            },
        )
        db.add(host_scan)
        db.commit()
        db.refresh(host_scan)

        new, updated = upsert_findings(
            db, asset.id, host_scan.id, raws,
            dast_monitor_id=monitor_id,
        )

        try:
            # Reusa correlator (passa monitor_id como "dast_scan_id" semanticamente).
            # Alternativa: estender correlator para aceitar monitor. Simplificamos.
            from app.core.dast.correlator import _fetch_sast_matches  # type: ignore
            from app.models import Finding

            # Correlator customizado: busca DAST sem cluster do monitor atual
            dast_findings = list(db.scalars(
                select(Finding).where(
                    Finding.dast_monitor_id == monitor_id,
                    Finding.cluster_id.is_(None),
                    Finding.status == "open",
                )
            ).all())
            _link_dast_monitor_to_sast(db, asset.id, dast_findings)
        except Exception:
            logger.exception("monitor correlator falhou (nao fatal)")

        monitor.last_poll_at = datetime.now(timezone.utc)
        monitor.next_poll_at = datetime.now(timezone.utc) + timedelta(
            seconds=monitor.poll_interval_s
        )
        monitor.polls_total += 1
        monitor.alerts_total = summary["alerts"]
        monitor.last_error = None
        db.commit()
        logger.info(
            "monitor %s poll ok: %d alerts (%d new, %d updated)",
            monitor_id, summary["alerts"], new, updated,
        )
    finally:
        db.close()


def _link_dast_monitor_to_sast(
    db: Session, asset_id: UUID, dast_findings: list,
) -> None:
    """Correlator por CWE para findings DAST sem cluster.

    Equivalente a `correlate_dast_sast` mas opera sobre lista de findings ja
    carregada (evita re-query por monitor).
    """
    from app.core.dast.correlator import (
        _correlatable_cwes,
        _fetch_sast_matches,
        _pick_existing_cluster,
        _ROOT_CAUSE_LABEL,
        _SOURCE_TAG,
    )
    from app.models import Cluster

    by_cwe: dict[str, list] = {}
    for f in dast_findings:
        for cwe in _correlatable_cwes(f):
            by_cwe.setdefault(cwe, []).append(f)

    for cwe, dast_group in by_cwe.items():
        sast = _fetch_sast_matches(db, asset_id, cwe)
        if not sast:
            continue
        cluster_id = _pick_existing_cluster(sast)
        if cluster_id is None:
            c = Cluster(
                asset_id=asset_id,
                root_cause=_ROOT_CAUSE_LABEL.get(cwe, f"{cwe} correlacionado DAST↔SAST"),
                confidence=0.85, source=_SOURCE_TAG,
            )
            db.add(c); db.flush()
            cluster_id = c.id
            for sf in sast:
                if sf.cluster_id is None:
                    sf.cluster_id = cluster_id
        for df in dast_group:
            if df.cluster_id is None:
                df.cluster_id = cluster_id
    db.commit()


# ---------------------------------------------------------------------------
# Enqueue (API handler)
# ---------------------------------------------------------------------------


def enqueue_monitor(
    db: Session,
    *,
    asset_id: UUID,
    target_url: str,
    poll_interval_s: int = 60,
    options: dict | None = None,
) -> DastMonitor:
    options = options or {}
    allow_private = bool(options.get("allow_private", False))
    try:
        validate_target_url(target_url, allow_private=allow_private)
    except SSRFError:
        raise

    monitor = DastMonitor(
        id=uuid4(),
        asset_id=asset_id,
        target_url=target_url.strip(),
        status="starting",
        poll_interval_s=max(15, min(poll_interval_s, 3600)),
        options=options,
    )
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return monitor
