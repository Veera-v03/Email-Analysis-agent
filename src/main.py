"""Application entry point for the Phase 1 foundation bootstrap."""

from __future__ import annotations

from pydantic import ValidationError

from src.config import get_settings
from src.models import EmailInput
from src.utils import configure_logging, get_logger, load_json_file

LOGGER = get_logger(__name__)


def format_email_summary(email: EmailInput) -> str:
    """Build a concise, non-analytical summary of a validated email.

    Args:
        email: Validated email input to summarize.

    Returns:
        Multi-line summary suitable for structured console logging.
    """
    return "\n".join(
        (
            "Validated sample email:",
            f"  Message ID: {email.header.message_id}",
            f"  From: {email.header.sender}",
            f"  To: {', '.join(email.header.recipients)}",
            f"  Subject: {email.header.subject}",
            f"  Attachments: {len(email.attachments)}",
        )
    )


def main() -> int:
    """Initialize the application and validate the bundled sample email.

    Returns:
        Process status code; zero on successful foundation validation.
    """
    settings = get_settings()
    config = settings.to_application_config()
    configure_logging(config.log_level)

    try:
        sample_path = config.data_directory / "samples" / "sample_email.json"
        sample_payload = load_json_file(sample_path)
        email = EmailInput.model_validate(sample_payload)
    except (FileNotFoundError, OSError, ValueError, ValidationError) as error:
        LOGGER.exception("Application bootstrap failed: %s", error)
        return 1

    LOGGER.info("%s %s started.", config.app_name, config.version)
    LOGGER.info("%s", format_email_summary(email))
    LOGGER.info("Foundation validation completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
