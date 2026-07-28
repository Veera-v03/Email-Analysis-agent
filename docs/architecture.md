# Architecture

## Layers and dependency direction

The system uses a Clean Architecture-oriented layout. `models` contains strict,
immutable Pydantic contracts and depends only on other model modules and third
party validation libraries. Parsers and analyzers depend on models; the Phase 5
runtime depends only on agent abstractions, registry interfaces, and models.
Tools adapt existing analyzers rather than reimplementing their business logic.

```text
config / utils
       |
parsers, sender analyzers, URL analyzers, attachment analyzers
       |
AgentTool adapters -> ToolRegistry -> ToolExecutionEngine
       |
AgentState, ToolResult, EvidenceCollection
```

All source modules import successfully as a set. There is no observed circular
dependency: models do not import analyzers, and the execution engine depends on
the registry interface rather than concrete tools.

## Phase 5 tool ecosystem

`AgentTool[T]` is the common execution contract. Each tool receives an
`AgentState`, returns a `ToolResult`, and can use `execute_with_handling()` for
consistent conversion of recoverable exceptions to failed results.

| Component | Responsibility |
|---|---|
| `ParserTool` | Converts raw state payloads to `EmailInput`; result updates parsed email. |
| `SenderTool` | Adapts `SenderIntelligenceEngine`. |
| `URLTool` | Adapts `UrlIntelligenceEngine`. |
| `AttachmentTool` | Coordinates modular attachment analyzers. |
| `ReportTool` | Summarizes centralized canonical evidence. |
| `ToolRegistry` | Registers and retrieves uniquely named tools. |
| `ToolExecutionEngine` | Resolves and executes tools in caller-provided order. |

## State, evidence, and execution flow

`AgentState` is the immutable single source of truth for parsed email, named
tool results, legacy compatibility evidence, canonical `EvidenceCollection`,
execution history, errors, and future planning placeholders. `with_tool_result`
is the one state transition used by the runtime.

```text
state + requested names/instances
  -> registry lookup (for names)
  -> execute_with_handling(current state)
  -> ToolResult
  -> AgentState.with_tool_result(...)
  -> next tool receives updated state
  -> ExecutionResult(final state, ordered results, summary)
```

Execution is sequential and deterministic. `ExecutionOptions.continue_on_failure`
defaults to `True`; a failed result is recorded and later tools continue. A
missing registry name becomes a recorded failed result. The engine neither
selects tools nor interprets evidence.

## Evidence framework

`Evidence` is the canonical serializable observation model. It provides an
identifier, type/category, title, description, severity, source, optional
confidence and recommendation, metadata, and timestamp. `EvidenceCollection`
is immutable and supports serialization and filtering. `EvidenceBuilder`
constructs records; `EvidenceAggregator` converts legacy `ToolEvidence`,
deduplicates records, and orders them by severity.

`ToolResult.evidence_collection` and `AgentState.evidence` are canonical.
`ToolEvidence` and `AgentState.accumulated_evidence` remain only for backwards
compatibility with earlier Phase 5 consumers.

## Attachment intelligence

`AttachmentTool` composes independent analyzers for metadata, signatures,
filename anomalies, entropy, hashing, archive contents, Office macros, PDFs,
and executables. It accepts attachment payloads from state metadata or email
attachment metadata, with an injectable deterministic reputation provider.

## Public extension points

- `AgentTool` for a new state-based capability.
- `IToolRegistry` for a registry implementation with different storage policy.
- `ExecutionOptions` for caller-owned deterministic execution policy.
- Attachment analyzer and reputation protocols for additional attachment checks.
- Existing sender and URL analyzer protocols for deeper domain capabilities.

## Public API reference

| API | Purpose |
|---|---|
| `AgentState.create()` | Creates the immutable workflow state. |
| `AgentState.with_tool_result()` | Applies a result, evidence, error, history record, and parsed-email output. |
| `ToolMetadata` | Stable identity and capabilities advertised by a tool. |
| `ToolResult` | Status, metadata, compatibility evidence, canonical evidence, duration, error, and optional parsed email. |
| `Evidence` / `EvidenceCollection` | Serializable canonical observations and their immutable collection. |
| `ToolRegistry.register()` / `get()` | Manages named tool discovery. |
| `ToolExecutionEngine.execute()` | Executes ordered names or instances and returns `ExecutionResult`. |
| `ExecutionResult` / `ExecutionSummary` | Final state plus ordered results and execution metrics. |

Public agent APIs are exported from `src.analyzers.agent`; core contracts are
also available from `src.models` where applicable.

Phase 6 can add a planner above the engine: it should produce an ordered tool
request and consume `ExecutionResult`, without changing current tools or state
transitions.
