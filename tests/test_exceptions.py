"""Tests for the XErr-code → exception mapping."""

import pytest

from mcapi_auth import _constants as c
from mcapi_auth.exceptions import (
    AdultVerificationRequiredError,
    ChildAccountError,
    NoXboxAccountError,
    RegionBlockedError,
    VerifyAgeRequiredError,
    XSTSError,
    xerr_to_exception,
)


@pytest.mark.parametrize(
    ("xerr", "expected_cls"),
    [
        (c.XERR_NO_XBOX_ACCOUNT, NoXboxAccountError),
        (c.XERR_REGION_BLOCKED, RegionBlockedError),
        (c.XERR_VERIFY_AGE_REQUIRED, VerifyAgeRequiredError),
        (c.XERR_REQUIRES_ADULT_VERIFICATION, AdultVerificationRequiredError),
        (c.XERR_CHILD_ACCOUNT, ChildAccountError),
    ],
)
def test_known_xerr_codes_map_to_typed_exceptions(xerr: int, expected_cls: type[XSTSError]) -> None:
    exc = xerr_to_exception(xerr)
    assert isinstance(exc, expected_cls)
    assert exc.xerr == xerr
    assert str(exc)  # nonempty message


def test_unknown_xerr_falls_back_to_generic_xsts_error() -> None:
    exc = xerr_to_exception(9999)
    assert type(exc) is XSTSError
    assert exc.xerr == 9999
    assert "9999" in str(exc)


def test_missing_xerr_still_yields_an_exception() -> None:
    exc = xerr_to_exception(None)
    assert isinstance(exc, XSTSError)
    assert exc.xerr is None


def test_missing_xerr_with_body_excerpt_includes_body_in_message() -> None:
    exc = xerr_to_exception(None, body_excerpt='{"Identity":"0"}')
    assert isinstance(exc, XSTSError)
    assert exc.xerr is None
    assert '{"Identity":"0"}' in str(exc)


def test_missing_xerr_with_long_body_truncates_to_300_chars() -> None:
    long_body = "x" * 500
    exc = xerr_to_exception(None, body_excerpt=long_body)
    rendered = str(exc)
    # 300-char excerpt + ellipsis + repr quoting; original body absent.
    assert "x" * 300 in rendered
    assert "…" in rendered
    assert "x" * 400 not in rendered


def test_missing_xerr_with_empty_body_excerpt_renders_empty_marker() -> None:
    exc = xerr_to_exception(None, body_excerpt="")
    assert isinstance(exc, XSTSError)
    assert "body=''" in str(exc)


def test_child_account_message_mentions_family_pack() -> None:
    exc = xerr_to_exception(c.XERR_CHILD_ACCOUNT)
    assert "Family" in str(exc) or "family" in str(exc)
