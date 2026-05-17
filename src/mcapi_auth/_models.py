"""Shared Pydantic plumbing.

Defines :class:`McModel`, the frozen base every response model in mcauth
inherits from, plus :data:`InstantField` for whenever-typed timestamps.

The aliasing strategy here is deliberately home-grown rather than using
``Field(alias=...)``: when an alias is set, Pydantic v2's PEP 681
``dataclass_transform`` exposes the alias as the ``__init__`` parameter
name (not the Python field name), which makes basedpyright reject
``Model(field_name=...)`` constructions in tests. By instead declaring
``__field_aliases__`` as a JSON-key → Python-field mapping and remapping
in a model validator, the dunder ``__init__`` keeps its natural Python
field names while we still parse Mojang's camelCase wire format.
"""

from __future__ import annotations

from typing import Annotated, Any, ClassVar

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer, model_validator
from whenever import Instant


def _coerce_instant(v: Any) -> Any:
    if isinstance(v, Instant):
        return v
    if isinstance(v, str):
        return Instant.parse_iso(v)
    raise TypeError(f"cannot parse {type(v).__name__} as whenever.Instant")


InstantField = Annotated[
    Instant,
    BeforeValidator(_coerce_instant),
    PlainSerializer(lambda i: i.format_iso(), return_type=str, when_used="json"),
]


class McModel(BaseModel):
    """Common Pydantic configuration for every response model in mcauth."""

    model_config = ConfigDict(
        frozen=True,
        extra="ignore",
        arbitrary_types_allowed=True,
    )

    # Subclasses override with {wire_key: python_field}.
    __field_aliases__: ClassVar[dict[str, str]] = {}

    @model_validator(mode="before")
    @classmethod
    def _apply_field_aliases(cls, data: Any) -> Any:
        aliases = cls.__field_aliases__
        if not aliases or not isinstance(data, dict):
            return data
        out: dict[str, Any] = dict(data)  # type: ignore[arg-type]
        for wire_key, py_field in aliases.items():
            if wire_key in out and py_field not in out:
                out[py_field] = out.pop(wire_key)
        return out
