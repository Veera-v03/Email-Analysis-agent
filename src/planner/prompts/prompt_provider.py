"""Concrete implementation of the PromptProvider interface."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.planner.exceptions.planner_exceptions import PromptLoadError
from src.planner.interfaces.planner import PromptProvider


class FileSystemPromptProvider(PromptProvider):
    """Loads prompt templates from the local filesystem."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        if templates_dir is None:
            self._templates_dir = Path(__file__).parent / "templates"
        else:
            self._templates_dir = templates_dir

    def get_prompt(self, template_name: str, **kwargs: Any) -> str:
        """Load and format a prompt template by name.

        Args:
            template_name: The name of the template file
                (with or without .txt extension).
            kwargs: Variables to format the template with.

        Returns:
            The formatted prompt string.

        Raises:
            PromptLoadError: If the template file cannot be found or formatted.
        """
        # Support both name and name.txt
        base_name = template_name
        if not base_name.endswith(".txt"):
            base_name = f"{base_name}.txt"

        template_path = self._templates_dir / base_name

        if not template_path.exists():
            raise PromptLoadError(
                f"Prompt template '{template_name}' not found at {template_path}"
            )

        try:
            with open(template_path, encoding="utf-8") as f:
                template_content = f.read()
        except Exception as e:
            raise PromptLoadError(
                f"Failed to read prompt template '{template_name}': {e}"
            ) from e

        try:
            return template_content.format(**kwargs)
        except KeyError as e:
            raise PromptLoadError(
                f"Missing variable {e} for formatting prompt template '{template_name}'"
            ) from e
        except Exception as e:
            raise PromptLoadError(
                f"Failed to format prompt template '{template_name}': {e}"
            ) from e


# For backward compatibility and ease of import
__all__ = ["FileSystemPromptProvider"]
