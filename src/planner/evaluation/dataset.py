"""Evaluation dataset of email scenarios for planner verification."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class EvaluationScenario(BaseModel):
    """Structured mock email scenario for evaluator validation."""

    name: str
    description: str
    headers: dict[str, str]
    body: str
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    expected_tools: list[str] = Field(default_factory=list)
    expected_strategy: str = "balanced"


SCENARIOS = [
    # 1. Newsletter
    EvaluationScenario(
        name="Newsletter",
        description="Standard monthly security updates newsletter.",
        headers={
            "message_id": "<news-1@trusted.com>",
            "sender": "security-updates@trustednewsletter.com",
            "subject": "Monthly Security Digest - July 2026",
            "sent_at": "2026-07-28T10:00:00Z",
        },
        body="Here is your monthly summary of updates. Check our archive for details.",
        expected_tools=["sender_tool"],
        expected_strategy="minimal",
    ),
    # 2. Marketing email
    EvaluationScenario(
        name="Marketing Email",
        description="Standard SaaS promotional offering with links.",
        headers={
            "message_id": "<promo-2@marketing.com>",
            "sender": "offers@promotions.saas.com",
            "subject": "Get 50% Off Premium Plan - Limited Time!",
            "sent_at": "2026-07-28T11:00:00Z",
        },
        body="Upgrade your account today: https://saas.com/promo-upgrade.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="balanced",
    ),
    # 3. Internal email
    EvaluationScenario(
        name="Internal Email",
        description="Trusted communications inside corporate domain.",
        headers={
            "message_id": "<internal-3@corp.com>",
            "sender": "ceo@corp.com",
            "subject": "All Hands Meeting Reminder",
            "sent_at": "2026-07-28T12:00:00Z",
        },
        body="Team, join us today at 2 PM for the quarterly company all-hands.",
        expected_tools=["sender_tool"],
        expected_strategy="minimal",
    ),
    # 4. Invoice scam
    EvaluationScenario(
        name="Invoice Scam",
        description="Phishing invoice scam from spoofed account with links.",
        headers={
            "message_id": "<scam-4@billing-support.com>",
            "sender": "billing-support@accounts-receivable.com",
            "subject": "URGENT: Outstanding Invoice #99837",
            "sent_at": "2026-07-28T13:00:00Z",
        },
        body="Please pay your overdue invoice immediately at: https://fake-billing-portal.net/pay.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="comprehensive",
    ),
    # 5. Credential phishing
    EvaluationScenario(
        name="Credential Phishing",
        description="Alert spoofing a system admin demanding immediate password verification.",
        headers={
            "message_id": "<alert-5@admin-support.com>",
            "sender": "admin@it-corp-alert.com",
            "subject": "Security Warning: Verify your account settings",
            "sent_at": "2026-07-28T14:00:00Z",
        },
        body="We detected suspicious logins. Re-authenticate here: https://it-corp-login.org/verify.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="comprehensive",
    ),
    # 6. BEC attack
    EvaluationScenario(
        name="BEC Attack",
        description="Business Email Compromise requesting gift cards.",
        headers={
            "message_id": "<bec-6@gmail.com>",
            "sender": "ceo.corp.mgt@gmail.com",
            "subject": "Urgent task from CEO",
            "sent_at": "2026-07-28T15:00:00Z",
        },
        body="I need you to buy 5 Apple gift cards immediately for a client meeting.",
        expected_tools=["sender_tool"],
        expected_strategy="emergency",
    ),
    # 7. Malware attachment
    EvaluationScenario(
        name="Malware Attachment",
        description="Direct executable masquerading as spreadsheet.",
        headers={
            "message_id": "<malware-7@invoice-office.com>",
            "sender": "shipping@invoice-office.com",
            "subject": "Shipping Documents",
            "sent_at": "2026-07-28T16:00:00Z",
        },
        body="Please review the attached spreadsheet for delivery information.",
        attachments=[
            {
                "filename": "invoice_doc.exe",
                "content_type": "application/octet-stream",
                "size": 10240,
            }
        ],
        expected_tools=["sender_tool", "attachment_tool"],
        expected_strategy="comprehensive",
    ),
    # 8. ZIP attachment
    EvaluationScenario(
        name="ZIP Attachment",
        description="Unknown sender delivering a compressed archive.",
        headers={
            "message_id": "<archive-8@delivery-docs.com>",
            "sender": "support@delivery-docs.com",
            "subject": "Required Archives",
            "sent_at": "2026-07-28T17:00:00Z",
        },
        body="See the attached zip containing raw report files.",
        attachments=[
            {
                "filename": "reports.zip",
                "content_type": "application/zip",
                "size": 25600,
            }
        ],
        expected_tools=["sender_tool", "attachment_tool"],
        expected_strategy="comprehensive",
    ),
    # 9. Unknown sender
    EvaluationScenario(
        name="Unknown Sender",
        description="Simple initial outreach message without attachments or links.",
        headers={
            "message_id": "<outreach-9@newventures.com>",
            "sender": "hello@newventures.com",
            "subject": "Partnership inquiry",
            "sent_at": "2026-07-28T18:00:00Z",
        },
        body="Hey, I'd love to jump on a quick 10-minute call to discuss synergies.",
        expected_tools=["sender_tool"],
        expected_strategy="balanced",
    ),
    # 10. Fake Microsoft login
    EvaluationScenario(
        name="Fake Microsoft Login",
        description="Office 365 credential harvesting link.",
        headers={
            "message_id": "<m365-10@office-secure.net>",
            "sender": "no-reply@office-secure.net",
            "subject": "Action Required: Re-activate Office365 subscription",
            "sent_at": "2026-07-28T19:00:00Z",
        },
        body="Your subscription has expired. Log in: https://microsoft-office365-billing.com/login.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="comprehensive",
    ),
    # 11. Bank phishing
    EvaluationScenario(
        name="Bank Phishing",
        description="Chase bank impersonation requiring verification.",
        headers={
            "message_id": "<chase-11@chase-secure-alerts.com>",
            "sender": "alerts@chase-secure-alerts.com",
            "subject": "Security Warning: Chase Account Locked",
            "sent_at": "2026-07-28T20:00:00Z",
        },
        body="Confirm your debit card identity immediately: https://chase-identity-verify.com/chase.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="comprehensive",
    ),
    # 12. GitHub notification
    EvaluationScenario(
        name="GitHub Notification",
        description="Notification for repository commits or issues.",
        headers={
            "message_id": "<github-12@github.com>",
            "sender": "noreply@github.com",
            "subject": "[GitHub] Security Alert: vulnerability in dependency",
            "sent_at": "2026-07-28T21:00:00Z",
        },
        body="An alert was triggered for repo: https://github.com/user/project/security/dependabot.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="balanced",
    ),
    # 13. Password reset
    EvaluationScenario(
        name="Password Reset",
        description="Transactional password reset request.",
        headers={
            "message_id": "<reset-13@accounts.com>",
            "sender": "no-reply@accounts.com",
            "subject": "Password reset request for your account",
            "sent_at": "2026-07-28T22:00:00Z",
        },
        body="Click here to reset password: https://accounts.com/reset?token=123.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="balanced",
    ),
    # 14. HR document
    EvaluationScenario(
        name="HR Document",
        description="Internal HR message with pdf attachment.",
        headers={
            "message_id": "<hr-14@corp.com>",
            "sender": "hr@corp.com",
            "subject": "Updated Employee Benefits Guide PDF",
            "sent_at": "2026-07-28T23:00:00Z",
        },
        body="Please review the attached PDF benefits guide.",
        attachments=[
            {
                "filename": "Benefits_2026.pdf",
                "content_type": "application/pdf",
                "size": 512000,
            }
        ],
        expected_tools=["sender_tool", "attachment_tool"],
        expected_strategy="balanced",
    ),
    # 15. Multiple URLs
    EvaluationScenario(
        name="Multiple URLs",
        description="SaaS digest report with multiple navigation links.",
        headers={
            "message_id": "<digest-15@saas.com>",
            "sender": "digest@saas.com",
            "subject": "Daily SaaS Digest Report",
            "sent_at": "2026-07-28T23:30:00Z",
        },
        body="View profile: https://saas.com/user. Settings: https://saas.com/settings. Help: https://saas.com/help.",
        expected_tools=["sender_tool", "url_tool"],
        expected_strategy="balanced",
    ),
    # 16. No URLs
    EvaluationScenario(
        name="No URLs",
        description="Basic plain text email with no links.",
        headers={
            "message_id": "<plain-16@friend.com>",
            "sender": "buddy@friend.com",
            "subject": "Coffee tomorrow?",
            "sent_at": "2026-07-28T23:45:00Z",
        },
        body="Hey, let's grab some coffee tomorrow at 10 AM. Let me know if that works.",
        expected_tools=["sender_tool"],
        expected_strategy="minimal",
    ),
    # 17. No attachment
    EvaluationScenario(
        name="No Attachment",
        description="Normal business inquiry without any files.",
        headers={
            "message_id": "<inquiry-17@client.com>",
            "sender": "sales@client.com",
            "subject": "Request for proposal details",
            "sent_at": "2026-07-28T23:50:00Z",
        },
        body="Could you send over the slides we discussed last week? Thanks.",
        expected_tools=["sender_tool"],
        expected_strategy="balanced",
    ),
    # 18. Multiple attachments
    EvaluationScenario(
        name="Multiple Attachments",
        description="Invoice delivery with multiple files attached.",
        headers={
            "message_id": "<multi-18@vendor.com>",
            "sender": "finance@vendor.com",
            "subject": "Invoice and receipts delivery",
            "sent_at": "2026-07-28T23:55:00Z",
        },
        body="Attached are the invoice PDF and receipt ZIP archives.",
        attachments=[
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "size": 45000,
            },
            {
                "filename": "receipts.zip",
                "content_type": "application/zip",
                "size": 120000,
            },
        ],
        expected_tools=["sender_tool", "attachment_tool"],
        expected_strategy="comprehensive",
    ),
]
