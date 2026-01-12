#!/usr/bin/env python3
"""
Shield Cross-Language Interoperability Tests

Verifies that ciphertext from one language can be decrypted in another.
This is CRITICAL for the 1.0.0 release claim: "Encrypt in any language, decrypt in any other."
"""

import sys
import os
import json
import subprocess
import tempfile
import base64

# Add Python shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from shield import Shield, quick_encrypt, quick_decrypt

# Test vectors - same password/service across all implementations
TEST_PASSWORD = "interop_test_password"
TEST_SERVICE = "interop.shield.test"
TEST_PLAINTEXT = b"Hello from Shield cross-language test!"
TEST_KEY = bytes.fromhex("0102030405060708091011121314151617181920212223242526272829303132")


def python_encrypt_shield():
    """Generate Shield ciphertext from Python."""
    s = Shield(TEST_PASSWORD, TEST_SERVICE)
    return s.encrypt(TEST_PLAINTEXT)


def python_decrypt_shield(ciphertext):
    """Decrypt Shield ciphertext in Python."""
    s = Shield(TEST_PASSWORD, TEST_SERVICE)
    return s.decrypt(ciphertext)


def python_encrypt_quick():
    """Generate quickEncrypt ciphertext from Python."""
    return quick_encrypt(TEST_KEY, TEST_PLAINTEXT)


def python_decrypt_quick(ciphertext):
    """Decrypt quickEncrypt ciphertext in Python."""
    return quick_decrypt(TEST_KEY, ciphertext)


def js_decrypt_shield(ciphertext_b64):
    """Decrypt Shield ciphertext in JavaScript."""
    js_code = f'''
const {{ Shield }} = require('./src/shield.js');
const ciphertext = Buffer.from('{ciphertext_b64}', 'base64');
const s = new Shield('{TEST_PASSWORD}', '{TEST_SERVICE}');
const decrypted = s.decrypt(ciphertext);
if (decrypted) {{
    console.log(decrypted.toString('utf8'));
}} else {{
    console.log('DECRYPT_FAILED');
}}
'''
    js_dir = os.path.join(os.path.dirname(__file__), '..', 'javascript')
    result = subprocess.run(
        ['node', '-e', js_code],
        cwd=js_dir,
        capture_output=True,
        text=True,
        timeout=30
    )
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    if output == 'DECRYPT_FAILED':
        return None
    return output.encode('utf8')


def js_encrypt_shield():
    """Generate Shield ciphertext from JavaScript."""
    js_code = f'''
const {{ Shield }} = require('./src/shield.js');
const s = new Shield('{TEST_PASSWORD}', '{TEST_SERVICE}');
const encrypted = s.encrypt(Buffer.from('{TEST_PLAINTEXT.decode()}'));
console.log(encrypted.toString('base64'));
'''
    js_dir = os.path.join(os.path.dirname(__file__), '..', 'javascript')
    result = subprocess.run(
        ['node', '-e', js_code],
        cwd=js_dir,
        capture_output=True,
        text=True,
        timeout=30
    )
    if result.returncode != 0:
        print(f"JS encrypt error: {result.stderr}")
        return None
    return base64.b64decode(result.stdout.strip())


def js_decrypt_quick(ciphertext_b64):
    """Decrypt quickEncrypt ciphertext in JavaScript."""
    key_hex = TEST_KEY.hex()
    js_code = f'''
const {{ quickDecrypt }} = require('./src/shield.js');
const key = Buffer.from('{key_hex}', 'hex');
const ciphertext = Buffer.from('{ciphertext_b64}', 'base64');
const decrypted = quickDecrypt(key, ciphertext);
if (decrypted) {{
    console.log(decrypted.toString('utf8'));
}} else {{
    console.log('DECRYPT_FAILED');
}}
'''
    js_dir = os.path.join(os.path.dirname(__file__), '..', 'javascript')
    result = subprocess.run(
        ['node', '-e', js_code],
        cwd=js_dir,
        capture_output=True,
        text=True,
        timeout=30
    )
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    if output == 'DECRYPT_FAILED':
        return None
    return output.encode('utf8')


def js_encrypt_quick():
    """Generate quickEncrypt ciphertext from JavaScript."""
    key_hex = TEST_KEY.hex()
    js_code = f'''
const {{ quickEncrypt }} = require('./src/shield.js');
const key = Buffer.from('{key_hex}', 'hex');
const encrypted = quickEncrypt(key, Buffer.from('{TEST_PLAINTEXT.decode()}'));
console.log(encrypted.toString('base64'));
'''
    js_dir = os.path.join(os.path.dirname(__file__), '..', 'javascript')
    result = subprocess.run(
        ['node', '-e', js_code],
        cwd=js_dir,
        capture_output=True,
        text=True,
        timeout=30
    )
    if result.returncode != 0:
        print(f"JS encrypt error: {result.stderr}")
        return None
    return base64.b64decode(result.stdout.strip())


def go_decrypt_shield(ciphertext_b64):
    """Decrypt Shield ciphertext in Go."""
    go_code = f'''
package main

import (
    "encoding/base64"
    "fmt"
    "github.com/Guard8-ai/shield/shield"
)

func main() {{
    ciphertext, _ := base64.StdEncoding.DecodeString("{ciphertext_b64}")
    s := shield.New("{TEST_PASSWORD}", "{TEST_SERVICE}")
    decrypted, err := s.Decrypt(ciphertext)
    if err != nil {{
        fmt.Println("DECRYPT_FAILED")
        return
    }}
    fmt.Print(string(decrypted))
}}
'''
    # Run Go code from the go/ directory where go.mod lives
    go_dir = os.path.join(os.path.dirname(__file__), '..', 'go')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False, dir=go_dir) as f:
        f.write(go_code)
        f.flush()
        try:
            result = subprocess.run(
                ['go', 'run', f.name],
                cwd=go_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode != 0:
                print(f"Go decrypt error: {result.stderr}")
                return None
            output = result.stdout
            if output == 'DECRYPT_FAILED':
                return None
            return output.encode('utf8')
        finally:
            os.unlink(f.name)


def go_encrypt_shield():
    """Generate Shield ciphertext from Go."""
    plaintext_b64 = base64.b64encode(TEST_PLAINTEXT).decode()
    go_code = f'''
package main

import (
    "encoding/base64"
    "fmt"
    "github.com/Guard8-ai/shield/shield"
)

func main() {{
    s := shield.New("{TEST_PASSWORD}", "{TEST_SERVICE}")
    plaintext, _ := base64.StdEncoding.DecodeString("{plaintext_b64}")
    encrypted, err := s.Encrypt(plaintext)
    if err != nil {{
        fmt.Println("ENCRYPT_FAILED")
        return
    }}
    fmt.Print(base64.StdEncoding.EncodeToString(encrypted))
}}
'''
    go_dir = os.path.join(os.path.dirname(__file__), '..', 'go')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False, dir=go_dir) as f:
        f.write(go_code)
        f.flush()
        try:
            result = subprocess.run(
                ['go', 'run', f.name],
                cwd=go_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode != 0:
                print(f"Go encrypt error: {result.stderr}")
                return None
            if result.stdout == 'ENCRYPT_FAILED':
                return None
            return base64.b64decode(result.stdout)
        finally:
            os.unlink(f.name)


def go_decrypt_quick(ciphertext_b64):
    """Decrypt quickEncrypt ciphertext in Go."""
    key_hex = TEST_KEY.hex()
    go_code = f'''
package main

import (
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "github.com/Guard8-ai/shield/shield"
)

func main() {{
    key, _ := hex.DecodeString("{key_hex}")
    ciphertext, _ := base64.StdEncoding.DecodeString("{ciphertext_b64}")
    decrypted, err := shield.QuickDecrypt(key, ciphertext)
    if err != nil {{
        fmt.Println("DECRYPT_FAILED")
        return
    }}
    fmt.Print(string(decrypted))
}}
'''
    go_dir = os.path.join(os.path.dirname(__file__), '..', 'go')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False, dir=go_dir) as f:
        f.write(go_code)
        f.flush()
        try:
            result = subprocess.run(
                ['go', 'run', f.name],
                cwd=go_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode != 0:
                return None
            output = result.stdout
            if output == 'DECRYPT_FAILED':
                return None
            return output.encode('utf8')
        finally:
            os.unlink(f.name)


def go_encrypt_quick():
    """Generate quickEncrypt ciphertext from Go."""
    key_hex = TEST_KEY.hex()
    plaintext_b64 = base64.b64encode(TEST_PLAINTEXT).decode()
    go_code = f'''
package main

import (
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "github.com/Guard8-ai/shield/shield"
)

func main() {{
    key, _ := hex.DecodeString("{key_hex}")
    plaintext, _ := base64.StdEncoding.DecodeString("{plaintext_b64}")
    encrypted, err := shield.QuickEncrypt(key, plaintext)
    if err != nil {{
        fmt.Println("ENCRYPT_FAILED")
        return
    }}
    fmt.Print(base64.StdEncoding.EncodeToString(encrypted))
}}
'''
    go_dir = os.path.join(os.path.dirname(__file__), '..', 'go')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False, dir=go_dir) as f:
        f.write(go_code)
        f.flush()
        try:
            result = subprocess.run(
                ['go', 'run', f.name],
                cwd=go_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode != 0:
                print(f"Go encrypt error: {result.stderr}")
                return None
            if result.stdout == 'ENCRYPT_FAILED':
                return None
            return base64.b64decode(result.stdout)
        finally:
            os.unlink(f.name)


class TestCrossLanguage:
    """Cross-language interoperability test suite."""

    def test_python_to_javascript_shield(self):
        """Python encrypts, JavaScript decrypts (Shield)."""
        ciphertext = python_encrypt_shield()
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = js_decrypt_shield(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Python → JavaScript (Shield)")

    def test_javascript_to_python_shield(self):
        """JavaScript encrypts, Python decrypts (Shield)."""
        ciphertext = js_encrypt_shield()
        assert ciphertext is not None, "JavaScript encryption failed"
        decrypted = python_decrypt_shield(ciphertext)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ JavaScript → Python (Shield)")

    def test_python_to_javascript_quick(self):
        """Python encrypts, JavaScript decrypts (quickEncrypt)."""
        ciphertext = python_encrypt_quick()
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = js_decrypt_quick(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Python → JavaScript (quickEncrypt)")

    def test_javascript_to_python_quick(self):
        """JavaScript encrypts, Python decrypts (quickEncrypt)."""
        ciphertext = js_encrypt_quick()
        assert ciphertext is not None, "JavaScript encryption failed"
        decrypted = python_decrypt_quick(ciphertext)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ JavaScript → Python (quickEncrypt)")

    def test_python_to_go_shield(self):
        """Python encrypts, Go decrypts (Shield)."""
        ciphertext = python_encrypt_shield()
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = go_decrypt_shield(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Python → Go (Shield)")

    def test_go_to_python_shield(self):
        """Go encrypts, Python decrypts (Shield)."""
        ciphertext = go_encrypt_shield()
        assert ciphertext is not None, "Go encryption failed"
        decrypted = python_decrypt_shield(ciphertext)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Go → Python (Shield)")

    def test_python_to_go_quick(self):
        """Python encrypts, Go decrypts (quickEncrypt)."""
        ciphertext = python_encrypt_quick()
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = go_decrypt_quick(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Python → Go (quickEncrypt)")

    def test_go_to_python_quick(self):
        """Go encrypts, Python decrypts (quickEncrypt)."""
        ciphertext = go_encrypt_quick()
        assert ciphertext is not None, "Go encryption failed"
        decrypted = python_decrypt_quick(ciphertext)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Go → Python (quickEncrypt)")

    def test_javascript_to_go_shield(self):
        """JavaScript encrypts, Go decrypts (Shield)."""
        ciphertext = js_encrypt_shield()
        assert ciphertext is not None, "JavaScript encryption failed"
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = go_decrypt_shield(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ JavaScript → Go (Shield)")

    def test_go_to_javascript_shield(self):
        """Go encrypts, JavaScript decrypts (Shield)."""
        ciphertext = go_encrypt_shield()
        assert ciphertext is not None, "Go encryption failed"
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = js_decrypt_shield(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Go → JavaScript (Shield)")

    def test_javascript_to_go_quick(self):
        """JavaScript encrypts, Go decrypts (quickEncrypt)."""
        ciphertext = js_encrypt_quick()
        assert ciphertext is not None, "JavaScript encryption failed"
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = go_decrypt_quick(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ JavaScript → Go (quickEncrypt)")

    def test_go_to_javascript_quick(self):
        """Go encrypts, JavaScript decrypts (quickEncrypt)."""
        ciphertext = go_encrypt_quick()
        assert ciphertext is not None, "Go encryption failed"
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        decrypted = js_decrypt_quick(ciphertext_b64)
        assert decrypted == TEST_PLAINTEXT, f"Expected {TEST_PLAINTEXT}, got {decrypted}"
        print("✓ Go → JavaScript (quickEncrypt)")


def test_key_derivation_consistency():
    """Verify all implementations derive the same key from password/service."""
    # Python key derivation
    s_py = Shield(TEST_PASSWORD, TEST_SERVICE)
    py_key = s_py._key.hex()

    # JavaScript key derivation
    js_code = f'''
const {{ Shield }} = require('./src/shield.js');
const s = new Shield('{TEST_PASSWORD}', '{TEST_SERVICE}');
console.log(s.key.toString('hex'));
'''
    js_dir = os.path.join(os.path.dirname(__file__), '..', 'javascript')
    result = subprocess.run(
        ['node', '-e', js_code],
        cwd=js_dir,
        capture_output=True,
        text=True,
        timeout=30
    )
    js_key = result.stdout.strip()

    # Go key derivation
    go_code = f'''
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/Guard8-ai/shield/shield"
)

func main() {{
    s := shield.New("{TEST_PASSWORD}", "{TEST_SERVICE}")
    fmt.Print(hex.EncodeToString(s.Key()))
}}
'''
    go_dir = os.path.join(os.path.dirname(__file__), '..', 'go')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False, dir=go_dir) as f:
        f.write(go_code)
        f.flush()
        try:
            result = subprocess.run(
                ['go', 'run', f.name],
                cwd=go_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            go_key = result.stdout.strip()
        finally:
            os.unlink(f.name)

    assert py_key == js_key, f"Python key {py_key} != JavaScript key {js_key}"
    assert py_key == go_key, f"Python key {py_key} != Go key {go_key}"
    print(f"✓ Key derivation consistent: {py_key[:16]}...")


def main():
    """Run all cross-language tests."""
    print("Shield Cross-Language Interoperability Tests")
    print("=" * 60)
    print(f"Test password: {TEST_PASSWORD}")
    print(f"Test service: {TEST_SERVICE}")
    print(f"Test plaintext: {TEST_PLAINTEXT.decode()}")
    print("=" * 60)

    # Key derivation first
    print("\n=== Key Derivation ===")
    test_key_derivation_consistency()

    # Cross-language tests
    print("\n=== Shield (Password-Based) ===")
    tests = TestCrossLanguage()

    tests.test_python_to_javascript_shield()
    tests.test_javascript_to_python_shield()
    tests.test_python_to_go_shield()
    tests.test_go_to_python_shield()
    tests.test_javascript_to_go_shield()
    tests.test_go_to_javascript_shield()

    print("\n=== QuickEncrypt (Pre-shared Key) ===")
    tests.test_python_to_javascript_quick()
    tests.test_javascript_to_python_quick()
    tests.test_python_to_go_quick()
    tests.test_go_to_python_quick()
    tests.test_javascript_to_go_quick()
    tests.test_go_to_javascript_quick()

    print("\n" + "=" * 60)
    print("All cross-language interoperability tests passed!")
    print("✓ Encrypt in any language, decrypt in any other: VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
