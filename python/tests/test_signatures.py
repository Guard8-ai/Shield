"""Tests for Shield signatures."""

import pytest
from shield.signatures import SymmetricSignature, LamportSignature


class TestSymmetricSignature:
    """Test SymmetricSignature class."""

    def test_sign_verify(self):
        """Sign and verify message."""
        signer = SymmetricSignature.generate()
        message = b"Hello, World!"
        sig = signer.sign(message)
        assert signer.verify(message, sig, signer.verification_key)

    def test_from_password(self):
        """Create from password."""
        signer = SymmetricSignature.from_password("password", "alice@example.com")
        message = b"test"
        sig = signer.sign(message)
        assert signer.verify(message, sig, signer.verification_key)

    def test_same_password_same_key(self):
        """Same password produces same key."""
        s1 = SymmetricSignature.from_password("password", "user@example.com")
        s2 = SymmetricSignature.from_password("password", "user@example.com")
        assert s1.verification_key == s2.verification_key

    def test_different_passwords(self):
        """Different passwords produce different keys."""
        s1 = SymmetricSignature.from_password("password1", "user")
        s2 = SymmetricSignature.from_password("password2", "user")
        assert s1.verification_key != s2.verification_key

    def test_tampered_message_fails(self):
        """Tampered message fails verification."""
        signer = SymmetricSignature.generate()
        sig = signer.sign(b"original")
        assert not signer.verify(b"tampered", sig, signer.verification_key)

    def test_tampered_signature_fails(self):
        """Tampered signature fails verification."""
        signer = SymmetricSignature.generate()
        sig = bytearray(signer.sign(b"message"))
        sig[10] ^= 0xFF
        assert not signer.verify(b"message", bytes(sig), signer.verification_key)

    def test_timestamp_included(self):
        """Signature includes timestamp."""
        signer = SymmetricSignature.generate()
        sig = signer.sign(b"message", include_timestamp=True)
        assert len(sig) == 40  # 8 timestamp + 32 signature

    def test_no_timestamp(self):
        """Signature without timestamp."""
        signer = SymmetricSignature.generate()
        sig = signer.sign(b"message", include_timestamp=False)
        assert len(sig) == 32

    def test_fingerprint(self):
        """Get key fingerprint."""
        signer = SymmetricSignature.generate()
        fp = signer.get_fingerprint()
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)


class TestLamportSignature:
    """Test LamportSignature class."""

    def test_sign_verify(self):
        """Sign and verify message."""
        lamport = LamportSignature.generate()
        message = b"Important document"
        sig = lamport.sign(message)
        assert LamportSignature.verify(message, sig, lamport.public_key)

    def test_one_time_use(self):
        """Key can only sign once."""
        lamport = LamportSignature.generate()
        lamport.sign(b"first message")
        with pytest.raises(RuntimeError):
            lamport.sign(b"second message")

    def test_is_used_flag(self):
        """is_used flag tracks usage."""
        lamport = LamportSignature.generate()
        assert not lamport.is_used
        lamport.sign(b"message")
        assert lamport.is_used

    def test_tampered_message_fails(self):
        """Tampered message fails verification."""
        lamport = LamportSignature.generate()
        sig = lamport.sign(b"original")
        assert not LamportSignature.verify(b"tampered", sig, lamport.public_key)

    def test_tampered_signature_fails(self):
        """Tampered signature fails verification."""
        lamport = LamportSignature.generate()
        public_key = lamport.public_key
        sig = bytearray(lamport.sign(b"message"))
        sig[100] ^= 0xFF
        assert not LamportSignature.verify(b"message", bytes(sig), public_key)

    def test_wrong_public_key_fails(self):
        """Wrong public key fails verification."""
        lamport1 = LamportSignature.generate()
        lamport2 = LamportSignature.generate()
        sig = lamport1.sign(b"message")
        assert not LamportSignature.verify(b"message", sig, lamport2.public_key)

    def test_signature_size(self):
        """Signature is correct size."""
        lamport = LamportSignature.generate()
        sig = lamport.sign(b"message")
        assert len(sig) == 256 * 32  # 8192 bytes

    def test_public_key_size(self):
        """Public key is correct size."""
        lamport = LamportSignature.generate()
        assert len(lamport.public_key) == 256 * 64  # 16384 bytes

    def test_fingerprint(self):
        """Get public key fingerprint."""
        lamport = LamportSignature.generate()
        fp = lamport.get_fingerprint()
        assert len(fp) == 16
