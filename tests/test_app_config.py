"""Tests for :class:`mcapi_auth.MsaApplicationConfig`."""

from mcapi_auth import (
    LIQUIDLAUNCHER_CLIENT_ID,
    MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    PRISM_LAUNCHER_CLIENT_ID,
    MsaApplicationConfig,
)
from mcapi_auth._constants import (
    LIVE_CONNECT_AUTHORIZE_URL,
    LIVE_CONNECT_TOKEN_URL,
    MSA_AUTHORIZE_URL,
    MSA_TOKEN_URL,
)


def test_v2_defaults_to_prism_and_v2_endpoints() -> None:
    cfg = MsaApplicationConfig.v2()
    assert cfg.client_id == PRISM_LAUNCHER_CLIENT_ID
    assert cfg.token_url == MSA_TOKEN_URL
    assert cfg.authorize_url == MSA_AUTHORIZE_URL
    assert cfg.is_v1 is False
    assert cfg.xbl_use_d_prefix is True


def test_v1_launcher_uses_live_connect_endpoints() -> None:
    cfg = MsaApplicationConfig.v1_launcher()
    assert cfg.client_id == MINECRAFT_LAUNCHER_V1_CLIENT_ID
    assert cfg.token_url == LIVE_CONNECT_TOKEN_URL
    assert cfg.authorize_url == LIVE_CONNECT_AUTHORIZE_URL
    assert cfg.is_v1 is True
    assert cfg.xbl_use_d_prefix is False


def test_from_known_resolves_alias_to_v2_config() -> None:
    cfg = MsaApplicationConfig.from_known("prism")
    assert cfg.client_id == PRISM_LAUNCHER_CLIENT_ID
    assert cfg.is_v1 is False
    # Prism's redirect override is recorded for display.
    assert cfg.redirect_uri == "http://127.0.0.1/"


def test_from_known_resolves_v1_alias_to_v1_config() -> None:
    cfg = MsaApplicationConfig.from_known("java")
    assert cfg.client_id == MINECRAFT_LAUNCHER_V1_CLIENT_ID
    assert cfg.is_v1 is True


def test_from_known_picks_up_liquidlauncher_redirect() -> None:
    cfg = MsaApplicationConfig.from_known("liquidlauncher")
    assert cfg.client_id == LIQUIDLAUNCHER_CLIENT_ID
    assert cfg.redirect_uri == "http://localhost/login"


def test_with_redirect_and_with_scope_return_copies() -> None:
    cfg = MsaApplicationConfig.v2()
    cfg2 = cfg.with_redirect("http://example.test/r")
    cfg3 = cfg.with_scope("XboxLive.signin")
    assert cfg2.redirect_uri == "http://example.test/r"
    assert cfg3.scope == "XboxLive.signin"
    # Originals unchanged (frozen dataclasses).
    assert cfg.redirect_uri is None
    assert cfg2.scope == cfg.scope
