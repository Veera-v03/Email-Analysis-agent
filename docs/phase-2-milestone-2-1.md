# Phase 2, Milestone 2.1: Parser contracts

This milestone establishes the extension boundary for the Email Parsing Engine.
It does not parse, inspect, or judge email content.

## Pipeline boundary

```text
RawEmail -> EmailLoader -> LoadedEmail -> EmailParser -> EmailInput
```

`RawEmail` carries an explicitly declared source kind (`json`, `eml`, or the
reserved future kind `msg`). This avoids relying on ambiguous content sniffing.
An `EmailLoader` converts every accepted representation to immutable bytes.
An `EmailParser` then receives only that canonical payload and returns the
existing normalized application contract.

## Design decisions

- Protocols provide dependency injection and independent unit testing without
  framework coupling or global registries.
- `StrEnum` makes source and stage values safe for structured log fields and
  configuration while retaining type safety.
- `ParserError` includes stage and non-sensitive source metadata, but never raw
  content, avoiding accidental disclosure in operational logs.
- The `MSG` source kind is reserved now. Future MSG support can add an
  implementation of `EmailLoader` without changing parser consumers.

## Trade-offs

The explicit source kind places a small responsibility on callers, but it is
more deterministic and auditable than auto-detection. Canonical bytes create a
clear parser interface, while a loader remains free to preserve original
encoding where that is required by a source format.

## Phase 1 integration

The contracts import the existing `EmailInput` model but do not alter the
Phase 1 startup path, sample fixture, configuration, or logging setup. Later
milestones will expand the normalized model and wire a parser into the
application composition root.
