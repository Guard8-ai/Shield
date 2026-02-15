---
id: backend-021
title: Add RecoveryCodes to C, Java, C#, Swift, Kotlin
status: done
priority: low
tags:
- backend
- feature-parity
- post-1.0.0
dependencies:
- backend-014
assignee: developer
created: 2026-01-11T19:47:05.700641127Z
estimate: 3h
complexity: 3
area: backend
---

# Add RecoveryCodes to C, Java, C#, Swift, Kotlin

## Causation Chain
> Trace the service orchestration: entry point → dependency injection →
business logic → side effects → return. Verify actual error propagation
paths in the codebase.

## Pre-flight Checks
- [ ] Read dependency task files for implementation context (Session Handoff)
- [ ] `grep -r "impl.*Service\|fn.*service" src/` - Find service definitions
- [ ] Check actual dependency injection patterns
- [ ] Verify error propagation through service layers
- [ ] `git log --oneline -10` - Check recent related commits

## Context
[Why this task exists and what problem it solves]

## Tasks
- [ ] [Specific actionable task]
- [ ] [Another task]
- [ ] Build + test + run to verify

## Acceptance Criteria
- [ ] [Testable criterion 1]
- [ ] [Testable criterion 2]

## Notes
[Technical details, constraints, gotchas]

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]