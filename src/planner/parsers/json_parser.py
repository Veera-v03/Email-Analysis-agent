"""Parser for validating and converting LLM text responses to Pydantic models."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from src.planner.exceptions.planner_exceptions import JSONValidationError

T = TypeVar("T", bound=BaseModel)


def clean_json_string(raw_text: str) -> str:
    """Clean LLM response, extracting JSON encapsulated in markdown fences."""
    text = raw_text.strip()

    # Matches ```json <content> ``` or ``` <content> ``` case-insensitively
    pattern = r"```(?:json)?\s*(.*?)\s*```"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        text = match.group(1).strip()

    return text


def parse_and_validate[T: BaseModel](raw_text: str, schema_class: type[T]) -> T:
    """Extract, parse, and validate JSON text into the specified Pydantic schema.

    Args:
        raw_text: The raw output string from the LLM provider.
        schema_class: The Pydantic model class to validate against.

    Returns:
        An instance of the schema_class Pydantic model.

    Raises:
        JSONValidationError: If parsing or schema validation fails.
    """
    cleaned = clean_json_string(raw_text)
    if not cleaned:
        raise JSONValidationError(
            "Response is empty or contains no extractable content.",
            details={"raw_text": raw_text},
        )

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise JSONValidationError(
            f"Failed to decode response as JSON. Error: {e}",
            details={"error": str(e), "cleaned_text": cleaned, "raw_text": raw_text},
        ) from e

    try:
        return schema_class.model_validate(data)
    except ValidationError as e:
        raise JSONValidationError(
            f"JSON validation failed for schema {schema_class.__name__}.",
            details={"validation_errors": e.errors(), "parsed_data": data},
        ) from e
