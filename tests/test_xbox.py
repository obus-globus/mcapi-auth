"""Tests for Xbox Live + XSTS stages."""

from __future__ import annotations

import pytest
import respx

from mcapi_auth._constants import XBL_AUTH_URL, XSTS_AUTH_URL
from mcapi_auth.auth.xbox import authenticate_xbl, authenticate_xsts
from mcapi_auth.exceptions import (
    AdultVerificationRequiredError,
    ChildAccountError,
    NoXboxAccountError,
    RegionBlockedError,
    VerifyAgeRequiredError,
    XboxAuthError,
    XSTSError,
)


@respx.mock
async def test_authenticate_xbl_extracts_token_and_userhash() -> None:
    respx.post(XBL_AUTH_URL).respond(
        json={"Token": "xbl-tok", "DisplayClaims": {"xui": [{"uhs": "uhs-abc"}]}}
    )
    result = await authenticate_xbl("msa-access")
    assert result.token == "xbl-tok"
    assert result.userhash == "uhs-abc"


@respx.mock
async def test_authenticate_xbl_raises_on_500() -> None:
    respx.post(XBL_AUTH_URL).respond(status_code=500, text="server down")
    with pytest.raises(XboxAuthError, match="status=500"):
        _ = await authenticate_xbl("msa-access")


@respx.mock
async def test_authenticate_xbl_raises_on_missing_userhash() -> None:
    respx.post(XBL_AUTH_URL).respond(json={"Token": "xbl-tok", "DisplayClaims": {"xui": [{}]}})
    with pytest.raises(XboxAuthError, match="missing required"):
        _ = await authenticate_xbl("msa-access")


@respx.mock
async def test_authenticate_xsts_happy_path() -> None:
    respx.post(XSTS_AUTH_URL).respond(
        json={"Token": "xsts-tok", "DisplayClaims": {"xui": [{"uhs": "uhs-xyz"}]}}
    )
    result = await authenticate_xsts("xbl-tok")
    assert result.token == "xsts-tok"
    assert result.userhash == "uhs-xyz"


@respx.mock
@pytest.mark.parametrize(
    ("xerr", "cls"),
    [
        (2148916233, NoXboxAccountError),
        (2148916235, RegionBlockedError),
        (2148916236, VerifyAgeRequiredError),
        (2148916237, AdultVerificationRequiredError),
        (2148916238, ChildAccountError),
    ],
)
async def test_authenticate_xsts_maps_known_xerr(xerr: int, cls: type[XSTSError]) -> None:
    respx.post(XSTS_AUTH_URL).respond(status_code=401, json={"XErr": xerr})
    with pytest.raises(cls) as info:
        _ = await authenticate_xsts("xbl-tok")
    assert info.value.xerr == xerr


@respx.mock
async def test_authenticate_xsts_unknown_xerr_falls_back() -> None:
    respx.post(XSTS_AUTH_URL).respond(status_code=401, json={"XErr": 999_999})
    with pytest.raises(XSTSError) as info:
        _ = await authenticate_xsts("xbl-tok")
    assert info.value.xerr == 999_999
    assert type(info.value) is XSTSError


@respx.mock
async def test_authenticate_xsts_401_without_xerr_still_raises() -> None:
    respx.post(XSTS_AUTH_URL).respond(status_code=401, json={"unexpected": True})
    with pytest.raises(XSTSError):
        _ = await authenticate_xsts("xbl-tok")


@respx.mock
async def test_authenticate_xsts_401_with_non_json_body_falls_back_to_generic() -> None:
    # Regression: a 401 with HTML/text body must still yield a typed XSTSError
    # rather than leaking the underlying MCAuthError raised by the JSON parser.
    respx.post(XSTS_AUTH_URL).respond(status_code=401, text="<html>access denied</html>")
    with pytest.raises(XSTSError) as info:
        _ = await authenticate_xsts("xbl-tok")
    assert info.value.xerr is None


@respx.mock
async def test_authenticate_xsts_401_with_json_array_falls_back_to_generic() -> None:
    # parse_json_object rejects non-object JSON; that branch must also map to XSTSError.
    respx.post(XSTS_AUTH_URL).respond(status_code=401, json=["denied"])
    with pytest.raises(XSTSError) as info:
        _ = await authenticate_xsts("xbl-tok")
    assert info.value.xerr is None


@respx.mock
async def test_authenticate_xbl_uses_d_prefix_by_default() -> None:
    import json as _json

    route = respx.post(XBL_AUTH_URL).respond(
        json={"Token": "t", "DisplayClaims": {"xui": [{"uhs": "u"}]}}
    )
    _ = await authenticate_xbl("msa-access")
    sent = _json.loads(route.calls.last.request.content)
    assert sent["Properties"]["RpsTicket"] == "d=msa-access"
    assert route.calls.last.request.headers.get("x-xbl-contract-version") == "1"


@respx.mock
async def test_authenticate_xbl_without_d_prefix() -> None:
    import json as _json

    route = respx.post(XBL_AUTH_URL).respond(
        json={"Token": "t", "DisplayClaims": {"xui": [{"uhs": "u"}]}}
    )
    _ = await authenticate_xbl("msa-access", use_d_prefix=False)
    sent = _json.loads(route.calls.last.request.content)
    assert sent["Properties"]["RpsTicket"] == "msa-access"
