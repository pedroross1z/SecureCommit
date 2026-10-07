"""Perfis DAST: validacao server-side + autorizacao."""
from __future__ import annotations

import pytest

from app.core.dast.profiles import get_profile, list_profiles


def test_list_profiles_has_four_known():
    names = {p.name for p in list_profiles()}
    assert names == {"passive", "baseline", "active", "full"}


def test_passive_is_safe_by_default():
    p = get_profile("passive")
    assert not p.requires_authorization
    assert p.passive_only is True


def test_baseline_is_safe_by_default():
    p = get_profile("baseline")
    assert not p.requires_authorization


def test_active_requires_authorization():
    assert get_profile("active").requires_authorization is True


def test_full_requires_authorization():
    assert get_profile("full").requires_authorization is True


def test_timeouts_bounded():
    for p in list_profiles():
        assert 0 < p.default_timeout_s <= p.max_timeout_s


def test_invalid_profile_rejected():
    with pytest.raises(ValueError, match="perfil invalido"):
        get_profile("yolo-full-send")
