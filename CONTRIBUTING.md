# Contributing

Use focused, backward-compatible changes. Preserve immutable state transitions and canonical evidence contracts. Add tests for behavior changes, run `ruff`, `mypy`, and relevant pytest suites, and avoid committing credentials or generated runtime data.

New tools implement `AgentTool`; external intelligence providers use the appropriate injected provider protocol; memory backends implement `IVectorStore`.
