"""SSRF guard: valida URLs de alvo do DAST contra loopback, privadas, metadata."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.core.dast.ssrf import SSRFError, validate_target_url


def _mock_resolve(ips: list[str]):
    """Patch socket.getaddrinfo para retornar IPs forjados."""
    def fake(host, port=None, *a, **kw):
        return [(2, 1, 6, "", (ip, 0)) for ip in ips]
    return patch("app.core.dast.ssrf.socket.getaddrinfo", side_effect=fake)


def test_blocks_non_http_scheme():
    with pytest.raises(SSRFError, match="schema"):
        validate_target_url("file:///etc/passwd")


def test_blocks_missing_host():
    with pytest.raises(SSRFError):
        validate_target_url("http:///path")


def test_blocks_loopback_ipv4():
    with _mock_resolve(["127.0.0.1"]):
        with pytest.raises(SSRFError, match="privado|loopback"):
            validate_target_url("http://localhost:8000")


def test_blocks_private_rfc1918():
    with _mock_resolve(["10.0.0.5"]):
        with pytest.raises(SSRFError, match="privado"):
            validate_target_url("http://internal.corp:8080")


def test_blocks_link_local():
    with _mock_resolve(["169.254.169.254"]):
        with pytest.raises(SSRFError):
            validate_target_url("http://metadata.svc")


def test_blocks_cloud_metadata_hostname():
    with pytest.raises(SSRFError, match="metadata"):
        validate_target_url("http://metadata.google.internal")


def test_blocks_disallowed_port():
    with _mock_resolve(["93.184.216.34"]):  # example.com
        with pytest.raises(SSRFError, match="porta"):
            validate_target_url("http://example.com:22")


def test_allows_public_http():
    with _mock_resolve(["93.184.216.34"]):
        v = validate_target_url("http://example.com")
        assert v.host == "example.com"
        assert v.port == 80
        assert "93.184.216.34" in v.resolved_ips


def test_allows_public_https():
    with _mock_resolve(["93.184.216.34"]):
        v = validate_target_url("https://example.com/path")
        assert v.scheme == "https"
        assert v.port == 443


def test_allowlist_bypass_requires_both_flag_and_env(monkeypatch):
    # Sem allowlist mesmo com allow_private=True, bloqueia.
    monkeypatch.delenv("DAST_ALLOWLIST_HOSTS", raising=False)
    with _mock_resolve(["127.0.0.1"]):
        with pytest.raises(SSRFError):
            validate_target_url("http://localhost:3000", allow_private=True)

    # Com allowlist + allow_private=True, passa.
    monkeypatch.setenv("DAST_ALLOWLIST_HOSTS", "localhost,juice.shop.lab")
    with _mock_resolve(["127.0.0.1"]):
        v = validate_target_url("http://localhost:3000", allow_private=True)
        assert v.host == "localhost"

    # Com allowlist mas sem allow_private, continua bloqueado.
    with _mock_resolve(["127.0.0.1"]):
        with pytest.raises(SSRFError):
            validate_target_url("http://localhost:3000", allow_private=False)
