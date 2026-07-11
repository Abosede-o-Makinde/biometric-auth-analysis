"""JSON reporter — serialises all result types to JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from biometric_auth.models.results import AttackResult, BiasResult, EvaluationResult, GDPRReport


def to_json(
    result: Union[EvaluationResult, BiasResult, AttackResult, GDPRReport],
    path: str | Path | None = None,
    indent: int = 2,
) -> str:
    """Serialise a result object to JSON.

    Args:
        result: Any result type with a ``to_dict()`` method.
        path: Optional file path to write to.
        indent: JSON indentation level.

    Returns:
        JSON string.
    """
    data = result.to_dict()
    text = json.dumps(data, indent=indent, default=str)
    if path is not None:
        Path(path).write_text(text, encoding="utf-8")
    return text
