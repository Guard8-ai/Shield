---
id: integration-005
title: Add HSM integration examples (PKCS#11)
status: done
priority: low
tags:
- integration
dependencies:
- setup-001
assignee: developer
created: 2026-01-11T17:45:38.171835297Z
estimate: 8h
complexity: 7
area: integration
---

# Add HSM integration examples (PKCS#11)

## Causation Chain
> Trace the integration boundary: our code → serialization → transport →
external API → response parsing → error mapping. Verify actual retry
logic and timeout handling in implementation.

## Pre-flight Checks
- [ ] Read dependency task files for implementation context (Session Handoff)
- [ ] `grep -r "fetch\|request\|Client::new" src/` - Find HTTP calls
- [ ] Check actual retry and timeout configuration
- [ ] Verify error mapping for external API responses
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