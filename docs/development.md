# Development Guide

## Quality gates

Python 3.13+ is required. Before merging, run:

```bash
python -m pytest
python -m ruff check .
python -m mypy src
```

Tests must remain deterministic: no live network calls, time-dependent
assertions, shared mutable state, or environmental assumptions.

## Conventions

- Keep modules single-purpose and dependencies explicit.
- Use complete type annotations and `from __future__ import annotations`.
- Use immutable Pydantic v2 boundary models with `extra="forbid"`, `strict=True`,
  and `frozen=True`.
- Put data contracts in `src/models`; do not import analyzers from models.
- Reuse existing analyzer engines through adapters. Do not duplicate analysis
  behavior in a new agent tool.
- Preserve `ToolEvidence` compatibility while emitting canonical evidence via
  `ToolResult.evidence_collection`.

## Working with the agent runtime

Register tools once in a `ToolRegistry`, then pass names to
`ToolExecutionEngine.execute`. Names preserve caller-controlled ordering;
instances are supported for embedded or test-only execution. Treat the returned
`ExecutionResult.state` as the next state—never mutate a prior `AgentState`.

See [tool development guide](tool-development-guide.md) for the required tool
contract and test checklist.
