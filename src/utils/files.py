"""Small file-loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json_file(file_path: Path) -> dict[str, Any]:
    """Load a JSON object from a UTF-8 encoded file.

    Args:
        file_path: Path to a JSON file whose root value must be an object.

    Returns:
        Parsed JSON object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the root JSON value is not an object.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    with file_path.open(encoding="utf-8") as source_file:
        payload: Any = json.load(source_file)

    if not isinstance(payload, dict):
        message = f"Expected a JSON object in '{file_path}'."
        raise ValueError(message)

    return payload
