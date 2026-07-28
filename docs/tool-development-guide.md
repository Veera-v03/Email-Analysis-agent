# Tool Development Guide

## Create a tool

1. Implement `AgentTool[AgentState]` in `src/analyzers/agent/tools/` (or the
   relevant bounded module).
2. Supply immutable `ToolMetadata` with a stable unique name, description,
   version, capabilities, and tags.
3. Read only the provided `AgentState`; return a `ToolResult`. Do not mutate
   dependencies or the state.
4. Reuse an existing analyzer through constructor injection when one exists.
5. Emit `ToolEvidence` with structured metadata. `ToolResult` automatically
   provides the canonical `EvidenceCollection`; new code may provide canonical
   evidence directly when appropriate.
6. Use `ToolExecutionStatus.SKIPPED` when input is absent but not erroneous.
   Raise `ToolValidationError` or `ToolExecutionError` for recoverable failures;
   the base wrapper converts them into an auditable failed result.

## Register and execute

```python
registry.register(MyTool())
outcome = ToolExecutionEngine(registry).execute(state, tools=["my_tool"])
next_state = outcome.state
```

The runtime adds results, canonical evidence, errors, and an `ExecutionRecord`
through `AgentState.with_tool_result`. It uses the result's `parsed_email` only
when a tool intentionally produces a normalized email contract.

## Best practices

- Keep tool names stable because they are `tool_results` keys and planner-facing
  identifiers.
- Keep metadata JSON-serializable and evidence descriptions self-contained.
- Do not hardcode tool order in tools or the execution engine.
- Do not embed planning, scoring, LLM calls, external APIs, or retries in Phase
  5 tools.
- Add unit tests for normal, skipped, and failed behavior; add an execution
  engine integration test for tools that depend on a prior state transition.
