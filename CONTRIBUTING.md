# Contributing to Shield

Thank you for considering contributing to Shield!

---

## The Note Test

Before submitting any change, ask yourself:

> "If I gave someone a note with this, would they know what to do?"

This applies to:
- Code comments
- Error messages
- Documentation
- API design

If the answer is "no," simplify until the answer is "yes."

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Guard8-ai/Shield.git
cd Shield

# Pick your language and run tests
cd python && python -m pytest      # Python
cd javascript && npm test          # JavaScript
cd go && go test ./...             # Go
cd c && make test                  # C
cd java && gradle test             # Java
cd wasm && cargo test              # WebAssembly
```

---

## What We Need Help With

### High Priority
- [ ] External security audit
- [ ] Performance benchmarks
- [ ] Formal verification of core algorithms
- [ ] Documentation improvements

### Medium Priority
- [ ] More test cases
- [ ] Edge case handling
- [ ] Error message improvements
- [ ] Examples for common use cases

### Language-Specific
- [ ] Ruby implementation
- [ ] PHP implementation
- [ ] Dart/Flutter implementation
- [ ] Erlang/Elixir implementation

---

## How to Contribute

### 1. Bug Reports

Open an issue with:
- What you expected
- What happened
- Steps to reproduce
- Your environment (OS, language version)

### 2. Feature Requests

Open an issue with:
- What you want to do
- Why it's useful
- How you'd use it

### 3. Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `python -m pytest` / `npm test` / `go test ./...`
5. Commit: `git commit -m "Add my feature"`
6. Push: `git push origin feature/my-feature`
7. Open a pull request

---

## Code Standards

### All Languages

- **Tests required**: No PR without tests
- **Byte compatibility**: Must produce identical output to Python reference
- **Constant-time**: Security-critical comparisons must be constant-time
- **Clear errors**: Error messages must explain what went wrong

### Python
```python
# Use type hints
def encrypt(self, plaintext: bytes) -> bytes:

# Use docstrings
"""Encrypt plaintext with the configured key.

Args:
    plaintext: Data to encrypt

Returns:
    Encrypted data with nonce and MAC
"""
```

### JavaScript
```javascript
// Use JSDoc
/**
 * Encrypt plaintext with the configured key.
 * @param {Buffer} plaintext - Data to encrypt
 * @returns {Buffer} Encrypted data with nonce and MAC
 */
```

### Go
```go
// Use godoc format
// Encrypt encrypts plaintext with the configured key.
// Returns encrypted data with nonce and MAC.
func (s *Shield) Encrypt(plaintext []byte) ([]byte, error)
```

---

## Testing Requirements

### Unit Tests

Every function needs tests:
```python
def test_encrypt_decrypt_roundtrip():
    s = Shield("password", "service")
    plaintext = b"Hello, World!"
    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)
    assert decrypted == plaintext
```

### Edge Cases

Test boundaries:
```python
def test_empty_plaintext():
    s = Shield("password", "service")
    encrypted = s.encrypt(b"")
    decrypted = s.decrypt(encrypted)
    assert decrypted == b""

def test_large_plaintext():
    s = Shield("password", "service")
    plaintext = b"x" * 10_000_000  # 10MB
    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)
    assert decrypted == plaintext
```

### Security Tests

Test failure cases:
```python
def test_tampered_ciphertext_fails():
    s = Shield("password", "service")
    encrypted = s.encrypt(b"secret")
    encrypted = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
    with pytest.raises(Exception):
        s.decrypt(encrypted)
```

### Cross-Language Tests

If adding a new language, add to `tests/test_interop.py`:
```python
def test_new_language_roundtrip():
    # Generate test vector in Python
    s = Shield("test", "service")
    encrypted = s.encrypt(b"hello")

    # Verify your implementation decrypts it
    result = subprocess.run([
        "your_language", "decrypt", encrypted.hex()
    ], capture_output=True)
    assert result.stdout.strip() == b"hello"
```

---

## Adding a New Language

1. **Create directory**: `new_language/`

2. **Implement core classes**:
   - `Shield` - Basic encryption
   - `RatchetSession` - Forward secrecy
   - `TOTP` - Two-factor auth
   - `SymmetricSignature` - HMAC signatures
   - `LamportSignature` - Quantum-safe signatures

3. **Match Python reference**:
   ```
   KEY_SIZE = 32
   NONCE_SIZE = 16
   MAC_SIZE = 16
   ITERATIONS = 100_000
   ```

4. **Write tests**: Minimum 15 tests covering core functionality

5. **Add to CHEATSHEET.md**: With code examples

6. **Add to INSTALL.md**: With installation instructions

7. **Add to README.md**: In the languages table

---

## Security Considerations

### Do NOT

- Introduce asymmetric cryptography (RSA, ECDSA, etc.)
- Reduce iteration count below 100,000
- Use non-constant-time comparisons for security checks
- Log or print key material
- Cache decrypted data unnecessarily

### Do

- Use cryptographically secure random number generators
- Wipe sensitive data from memory when possible
- Return clear error messages without leaking secrets
- Test all failure paths

---

## Commit Messages

Format:
```
<type>(<scope>): <description>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Adding tests
- `refactor`: Code restructuring
- `perf`: Performance improvement
- `chore`: Maintenance

Examples:
```
feat(python): add GroupEncryption class

Implements multi-recipient encryption for team messaging.

Closes #42
```

```
fix(javascript): correct TOTP window verification

Was checking wrong time window direction.
```

---

## Pull Request Process

1. **Title**: Clear, concise description
2. **Description**: What, why, and how
3. **Tests**: All tests passing
4. **Docs**: Updated if needed
5. **Review**: Wait for maintainer review
6. **Merge**: Squash and merge

---

## Code of Conduct

- Be respectful
- Be constructive
- Be patient
- No harassment
- No discrimination

Violations will result in removal from the project.

---

## Questions?

- Open an issue with the "question" label
- Email: contribute@guard8.ai

Thank you for helping make Shield better!
