# Module 20 Architecture: Enterprise SOC Alerting, Multi-Channel Notification & Webhook Dispatch Engine

## 1. Overview & Architectural Role

**Module 20** provides the enterprise alerting and external notification subsystem for the ScamON Email Analysis Agent. It bridges internal security domain events (`RemediationExecutedEvent`, `RiskScoredEvent`, `AnalyticsAggregatedEvent`) to external Security Operations Center (SOC) communication channels:
- **Slack**: Formatted alert messages using Slack Block Kit JSON.
- **Microsoft Teams**: Formatted adaptive cards and MessageCard payloads.
- **Generic Outbound Webhook**: JSON payloads secured with **HMAC-SHA256 signatures** and protected by **SSRF guardrails**.
- **SMTP Email**: Structured HTML/plain text security notifications.

```text
               ┌────────────────────────────────────────────────────────┐
               │         ScamON EventBus (InMemory / RedisStreams)      │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                 (RemediationExecuted, RiskScored, AnalyticsAggregated)
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │     NotificationEventSubscriber       │
                      └───────────────────┬───────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │          NotificationEngine           │
                      │  - PII & Secret Sanitizer             │
                      │  - In-Memory Rate Limiting (Token)    │
                      │  - Threat Alert Deduplication         │
                      │  - Bounded Exponential Backoff/Jitter │
                      │  - SSRF URL Pre-validation            │
                      └───────┬──────────┬──────────┬─────────┘
                              │          │          │         │
                 ┌────────────┘          │          │         └────────────┐
                 ▼                       ▼          ▼                      ▼
        ┌─────────────────┐    ┌─────────────────┐  ┌────────────────┐ ┌────────────────┐
        │SlackAsyncChannel│    │TeamsAsyncChannel│  │WebhookAsyncChan│ │EmailAsyncChan  │
        └─────────────────┘    └─────────────────┘  └────────────────┘ └────────────────┘
```

---

## 2. Core Subsystem Components

| Component | File Path | Responsibility |
| :--- | :--- | :--- |
| `NotificationEngine` | `src/notifications/engine.py` | Central asynchronous dispatcher coordinating multi-channel fan-out, retries, rate limits, and dedup. |
| `NotificationModule` | `src/notifications/module.py` | Lifecycle management implementing `IModule` and `IHealthCheckable` with DI bindings. |
| `NotificationEventSubscriber` | `src/notifications/subscribers.py` | EventBus listener translating domain security events into notification payloads. |
| `PayloadSanitizer` | `src/notifications/sanitizer.py` | Redacts sensitive credentials, tokens, API keys, passwords, and raw email message bodies. |
| `SlackAsyncChannel` | `src/notifications/channels/slack.py` | Formats and posts alerts to Slack Incoming Webhooks via Block Kit. |
| `TeamsAsyncChannel` | `src/notifications/channels/teams.py` | Formats and posts alerts to Microsoft Teams Webhooks via Adaptive Cards. |
| `WebhookAsyncChannel` | `src/notifications/channels/webhook.py` | Outbound JSON webhook delivery with HMAC-SHA256 signature headers and SSRF checking. |
| `EmailAsyncChannel` | `src/notifications/channels/email.py` | Asynchronous SMTP delivery via threadpool with simulated logger fallback. |
| `NotificationDispatcher` | `src/notifications/notifier.py` | Backward-compatible synchronous adapter preserving legacy SIEM export integrations. |

---

## 3. Mandatory Security Controls

### 3.1 Strict Tenant Isolation
- Every alert payload contains a validated `tenant_id`.
- Tenant routing configurations (`TenantNotificationConfigDTO`) isolate webhook URLs, recipients, rate limits, and signing keys per tenant.

### 3.2 Automated PII & Secret Sanitization
- Prior to transmission across any external channel, all notification payloads are processed by `sanitize_payload()`.
- Strips:
  - Bearer tokens (`Bearer eyJ...`)
  - Passwords and credential pairs (`password: ...`)
  - OpenAI / Groq API keys (`sk-...`, `gsk_...`)
  - Raw email message bodies and full MIME payloads.

### 3.3 Webhook Server-Side Request Forgery (SSRF) Protection
- Validates URL scheme is strictly `http` or `https`.
- Resolves all destination DNS records immediately prior to connection.
- Rejects any destination IP residing within:
  - `127.0.0.0/8` and `::1` (Loopback)
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private Networks)
  - `169.254.0.0/16` (Link-local / Cloud Metadata Endpoints: `169.254.169.254`)
  - `0.0.0.0/8`, `fc00::/7`, `fe80::/10` (Reserved / Local IPv6)
- Rejects blocked internal hostnames (`localhost`, `metadata.google.internal`, `*.internal`, `*.local`).

### 3.4 HMAC-SHA256 Webhook Request Signing
- Webhook payloads include the following authenticity headers:
  - `X-ScamON-Signature: sha256=<hex_digest>`
  - `X-ScamON-Timestamp: <epoch_seconds>`
  - `X-ScamON-Event: <event_name>`
  - `X-ScamON-Tenant: <tenant_id>`
- Signature calculation: $\text{HMAC-SHA256}(K, T \mathbin{\Vert} \text{"."} \mathbin{\Vert} \text{Payload})$.

---

## 4. Operational Telemetry & Resilience

- **Non-blocking Execution**: Network failures on third-party webhooks are caught and recorded as `DeliveryStatus.FAILED` without interrupting the email pipeline or throwing unhandled errors into the EventBus.
- **Rate-Limiting**: Sliding window in-memory rate limiter per tenant (default: 60 msgs/min) preventing webhook flooding.
- **Deduplication**: Suppresses repeated notifications for the same `tenant_id:event_name:incident_id` within a configurable window (default: 300s).
- **Retry Policy**: Bounded exponential backoff with randomized jitter ($\le 3$ retries).
