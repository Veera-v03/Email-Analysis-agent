"""Unit tests for JSON parsing and validation utilities."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, StrictInt, StrictStr

from src.planner.exceptions.planner_exceptions import JSONValidationError
from src.planner.parsers.json_parser import clean_json_string, parse_and_validate


class SimpleSchema(BaseModel):
    name: StrictStr
    value: StrictInt


def test_clean_json_string() -> None:
    """Verify that json markdown fences are cleaned correctly."""
    raw_markdown = '```json\n{\n  "name": "test"\n}\n```'
    assert clean_json_string(raw_markdown) == '{\n  "name": "test"\n}'

    raw_plain = '{\n  "name": "test"\n}'
    assert clean_json_string(raw_plain) == '{\n  "name": "test"\n}'

    raw_no_json_fence = '```\n{\n  "name": "test"\n}\n```'
    assert clean_json_string(raw_no_json_fence) == '{\n  "name": "test"\n}'


def test_parse_and_validate_success() -> None:
    """Ensure a valid json string with schema matches successfully."""
    raw = '{"name": "hello", "value": 123}'
    parsed = parse_and_validate(raw, SimpleSchema)
    assert parsed.name == "hello"
    assert parsed.value == 123


def test_parse_and_validate_with_markdown_success() -> None:
    """Ensure markdown wrapped JSON string resolves successfully."""
    raw = '```json\n{\n  "name": "hello",\n  "value": 123\n}\n```'
    parsed = parse_and_validate(raw, SimpleSchema)
    assert parsed.name == "hello"
    assert parsed.value == 123


def test_parse_and_validate_decode_error() -> None:
    """Verify invalid JSON syntax triggers a JSONValidationError."""
    raw_bad = '{"name": "hello", "value": 123,'
    with pytest.raises(JSONValidationError) as excinfo:
        parse_and_validate(raw_bad, SimpleSchema)
    assert "Failed to decode response as JSON" in str(excinfo.value)
    assert "cleaned_text" in excinfo.value.details


def test_parse_and_validate_schema_validation_error() -> None:
    """Verify JSON with invalid schema types/fields triggers a JSONValidationError."""
    raw_bad = '{"name": "hello", "value": "not-an-int"}'
    with pytest.raises(JSONValidationError) as excinfo:
        parse_and_validate(raw_bad, SimpleSchema)
    assert "JSON validation failed for schema SimpleSchema" in str(excinfo.value)
    assert "validation_errors" in excinfo.value.details
