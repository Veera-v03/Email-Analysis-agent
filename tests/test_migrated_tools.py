from __future__ import annotations

from src.analyzers.agent.attachments import AttachmentTool
from src.analyzers.agent.registry import ToolRegistry
from src.analyzers.agent.tools.parser_tool import ParserTool
from src.analyzers.agent.tools.report_tool import ReportTool
from src.analyzers.agent.tools.sender_tool import SenderTool
from src.analyzers.agent.tools.url_tool import URLTool
from src.models.agent import AgentState, ToolCapability, ToolExecutionStatus
from src.models.email import EmailHeader, EmailInput
from src.models.evidence import Evidence


def test_parser_tool_execution() -> None:
    tool = ParserTool()
    raw_email_dict = {
        "header": {
            "message_id": "<parsed_1@example.com>",
            "sender": "alice@example.com",
            "recipients": ["bob@example.com"],
            "subject": "Parsed Email Subject",
            "sent_at": "2026-07-28T10:00:00Z",
        },
        "body_text": "Hello, check this link: http://example.com/login",
    }
    state = AgentState.create(metadata={"raw_email": raw_email_dict})

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.metadata["parsed"] is True
    assert result.metadata["message_id"] == "<parsed_1@example.com>"
    assert len(result.evidence) == 1
    assert result.evidence[0].category == "parser"
    assert isinstance(result.evidence_collection.items[0], Evidence)


def test_sender_tool_execution() -> None:
    tool = SenderTool()
    email = EmailInput(
        header=EmailHeader(
            message_id="<sender_1@example.com>",
            sender="admin@example.com",
            recipients=["user@example.com"],
            subject="Security Notice",
            sent_at="2026-07-28T11:00:00Z",
        ),
        body_text="Please review your account",
    )
    state = AgentState.create(parsed_email=email)

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.metadata["from_sender"] == "admin@example.com"
    assert len(result.evidence) >= 2


def test_url_tool_execution() -> None:
    tool = URLTool()
    email = EmailInput(
        header=EmailHeader(
            message_id="<url_1@example.com>",
            sender="newsletter@example.com",
            recipients=["reader@example.com"],
            subject="Weekly Update",
            sent_at="2026-07-28T12:00:00Z",
        ),
        body_text="Visit http://bit.ly/3xyz for login details",
    )
    state = AgentState.create(parsed_email=email)

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.metadata["total_urls_extracted"] == 1
    assert result.metadata["shortened_url_count"] == 1
    assert len(result.evidence) >= 1


def test_report_tool_execution() -> None:
    report_tool = ReportTool()
    sender_tool = SenderTool()
    url_tool = URLTool()

    email = EmailInput(
        header=EmailHeader(
            message_id="<report_1@example.com>",
            sender="alert@phish.example",
            recipients=["target@example.com"],
            subject="Urgent Verification Required",
            sent_at="2026-07-28T13:00:00Z",
        ),
        body_text="Click http://short.url/verify to confirm",
    )
    initial_state = AgentState.create(parsed_email=email)

    # Execute tools and update state
    sender_res = sender_tool.execute(initial_state)
    state_after_sender = initial_state.with_tool_result(sender_res)

    url_res = url_tool.execute(state_after_sender)
    state_after_url = state_after_sender.with_tool_result(url_res)
    assert state_after_url.evidence.items
    assert {item.source for item in state_after_url.evidence.items} == {
        "sender_tool",
        "url_tool",
    }

    # Run ReportTool on state
    report_res = report_tool.execute(state_after_url)

    assert report_res.status is ToolExecutionStatus.COMPLETED
    assert report_res.metadata["tools_executed_count"] == 2
    assert report_res.metadata["total_evidence_count"] >= 2
    assert report_res.evidence[0].category == "diagnostic_report"


def test_tool_registry_with_all_migrated_tools() -> None:
    registry = ToolRegistry()

    parser_tool = ParserTool()
    sender_tool = SenderTool()
    url_tool = URLTool()
    attachment_tool = AttachmentTool()
    report_tool = ReportTool()

    registry.register(parser_tool)
    registry.register(sender_tool)
    registry.register(url_tool)
    registry.register(attachment_tool)
    registry.register(report_tool)

    assert len(registry.list_tools()) == 5
    assert registry.get("parser_tool") is parser_tool
    assert registry.get("sender_tool") is sender_tool
    assert registry.get("url_tool") is url_tool
    assert registry.get("attachment_tool") is attachment_tool
    assert registry.get("report_tool") is report_tool

    # Test filtering by capabilities
    assert registry.filter_by_capability(ToolCapability.PARSER) == [parser_tool]
    assert registry.filter_by_capability(ToolCapability.SENDER) == [sender_tool]
    assert registry.filter_by_capability(ToolCapability.URL) == [url_tool]
    assert registry.filter_by_capability(ToolCapability.ATTACHMENT) == [attachment_tool]
