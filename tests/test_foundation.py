"""Foundation behaviour tests."""

from __future__ import annotations

from src.config.settings import get_settings
from src.main import main
from src.models import EmailInput
from src.utils import load_json_file


def test_sample_email_validates() -> None:
    """The committed sample email conforms to the strict input contract."""
    settings = get_settings()
    payload = load_json_file(settings.data_directory / "samples" / "sample_email.json")

    email = EmailInput.model_validate(payload)

    assert email.header.subject == "Action required: verify your account information"
    assert len(email.attachments) == 1


def test_bootstrap_exits_successfully() -> None:
    """The Phase 1 application entry point completes without errors."""
    assert main() == 0
