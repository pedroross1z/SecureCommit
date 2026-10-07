"""SSRF guard para URLs de destino do DAST.

Bloqueia loopback, link-local, redes privadas, metadados de cloud,
portas sensiveis e schemas nao-HTTP. Resolve o host via DNS e valida
TODOS os endereços retornados — nao basta rejeitar `localhost` por nome.

Use `validate_target_url(url)` antes de qualquer requisicao ao destino.
Para habilitar alvos privados em laboratorio, informe allowlist via env
`DAST_ALLOWLIST_HOSTS` (hostnames separados por virgula).
"""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}

# Portas tipicamente usadas em HTTP(s). Rejeitamos o resto por padrao.
_ALLOWED_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9090}

# Hostnames de metadata de cloud (reforco explicito alem do bloqueio de IP).
_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "metadata.aws",
    "instance-data",
    "instance-data.ec2.internal",
}

# Endereco IMDS AWS/Azure/GCP (169.254.169.254 ja cai em link-local, mas documento).
_METADATA_IPS = {
    "169.254.169.254",
    "fd00:ec2::254",
}


class SSRFError(ValueError):
    """URL rejeitada pelo SSRF guard."""


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    resolved_ips: tuple[str, ...]


def _allowlist() -> set[str]:
    raw = os.environ.get("DAST_ALLOWLIST_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve(host: str) -> list[str]:
    """Resolve host para todos os IPs (v4 e v6). Levanta SSRFError se falhar."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SSRFError(f"host nao resolvido: {host} ({e})") from e
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ip = sockaddr[0]
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        raise SSRFError(f"host sem IPs: {host}")
    return ips


def validate_target_url(url: str, *, allow_private: bool = False) -> ValidatedTarget:
    """Valida URL para uso como alvo DAST.

    - `allow_private=True` permite loopback/privadas se o host estiver na
      allowlist via `DAST_ALLOWLIST_HOSTS`. Util para laboratorio local
      com Juice Shop/pygoat.
    """
    if not url or len(url) > 2048:
        raise SSRFError("url invalida (vazia ou muito longa)")

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFError(f"schema nao permitido: {scheme!r} (use http/https)")

    host = (parsed.hostname or "").lower()
    if not host:
        raise SSRFError("url sem hostname")

    if host in _METADATA_HOSTS:
        raise SSRFError(f"host de metadata bloqueado: {host}")

    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in _ALLOWED_PORTS:
        raise SSRFError(f"porta nao permitida: {port}")

    allowlist = _allowlist()
    in_allowlist = allow_private and host in allowlist

    ips = _resolve(host)

    for raw_ip in ips:
        if raw_ip in _METADATA_IPS:
            raise SSRFError(f"IP de metadata bloqueado: {raw_ip}")
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            raise SSRFError(f"IP invalido: {raw_ip}")
        if _is_private(ip_obj) and not in_allowlist:
            raise SSRFError(
                f"IP privado/loopback/link-local bloqueado: {raw_ip}"
                f" (host {host}). Para laboratorio, autorize via DAST_ALLOWLIST_HOSTS."
            )

    return ValidatedTarget(
        url=url.strip(),
        scheme=scheme,
        host=host,
        port=port,
        resolved_ips=tuple(ips),
    )
