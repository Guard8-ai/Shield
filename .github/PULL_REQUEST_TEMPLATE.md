## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring (no functional changes)

## Language(s) Affected
- [ ] Rust (shield-core)
- [ ] Python
- [ ] JavaScript
- [ ] Go
- [ ] Java
- [ ] C#
- [ ] C
- [ ] Swift
- [ ] Kotlin
- [ ] WebAssembly
- [ ] Documentation only

## Testing
- [ ] I have run the tests for the affected language(s)
- [ ] I have added tests that prove my fix/feature works
- [ ] All new and existing tests pass

```bash
# Commands used to test
cd shield-core && cargo test --features async
cd python && python -m pytest
cd javascript && npm test
```

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code where necessary
- [ ] I have updated the documentation (if applicable)
- [ ] My changes generate no new warnings
- [ ] I have checked for cross-language compatibility (if applicable)

## Security Checklist (for crypto changes)
- [ ] No hardcoded keys or secrets
- [ ] Constant-time comparisons used where needed
- [ ] No new dependencies without security review
- [ ] HMAC/authentication not weakened
- [ ] Key derivation parameters unchanged (or explicitly approved)

## Breaking Changes
If this is a breaking change, describe what breaks and the migration path.

## Related Issues
Fixes #(issue number)
