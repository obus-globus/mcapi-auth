"""Catch drift between ``pyproject.toml`` and ``mcapi_auth.__version__``."""

from __future__ import annotations

import tomllib
from pathlib import Path

import mcapi_auth


def test_version_matches_pyproject() -> None:
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject_path.open("rb") as fp:
        data = tomllib.load(fp)
    declared = data["project"]["version"]
    assert mcapi_auth.__version__ == declared, (
        f"mcapi_auth.__version__={mcapi_auth.__version__!r} does not match "
        f"pyproject.toml project.version={declared!r}"
    )


def test_version_is_semver() -> None:
    parts = mcapi_auth.__version__.split(".")
    assert len(parts) >= 3, f"expected semver MAJOR.MINOR.PATCH, got {mcapi_auth.__version__!r}"
    # First two are always pure ints; PATCH may carry a +local / -rc suffix
    int(parts[0])
    int(parts[1])
