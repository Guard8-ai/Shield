"""
Shield + AWS CloudHSM Integration Example

This example shows how to use AWS CloudHSM to protect Shield encryption keys
using the PKCS#11 interface.

Prerequisites:
    - AWS CloudHSM cluster configured
    - CloudHSM client installed
    - pip install PyKCS11 shield-crypto

Setup:
    export CLOUDHSM_ROLE=crypto_user
    export CLOUDHSM_PASSWORD=your-password
"""

import os
import hashlib
from typing import Optional

# PKCS#11 constants
CKM_AES_KEY_GEN = 0x00001080
CKM_AES_CBC_PAD = 0x00001085
CKA_CLASS = 0x00000000
CKA_KEY_TYPE = 0x00000100
CKA_TOKEN = 0x00000001
CKA_LABEL = 0x00000003
CKA_ENCRYPT = 0x00000104
CKA_DECRYPT = 0x00000105
CKA_VALUE_LEN = 0x00000161
CKO_SECRET_KEY = 0x00000004
CKK_AES = 0x0000001F


class CloudHSMKeyProvider:
    """
    Key provider using AWS CloudHSM via PKCS#11.

    Keys are generated and stored in the HSM. They never leave the
    hardware boundary.
    """

    def __init__(self, library_path: str = '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
                 slot: int = 0, pin: Optional[str] = None,
                 key_label: str = 'shield-master-key'):
        """
        Initialize CloudHSM provider.

        Args:
            library_path: Path to CloudHSM PKCS#11 library
            slot: HSM slot number
            pin: HSM user PIN (or set CLOUDHSM_PASSWORD env var)
            key_label: Label for the master key
        """
        try:
            import PyKCS11
        except ImportError:
            raise ImportError("PyKCS11 required: pip install PyKCS11")

        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(library_path)

        self.slot = slot
        self.pin = pin or os.environ.get('CLOUDHSM_PASSWORD')
        self.key_label = key_label
        self.session = None

        if not self.pin:
            raise ValueError("HSM PIN required (set CLOUDHSM_PASSWORD)")

    def _get_session(self):
        """Get or create PKCS#11 session."""
        if self.session is None:
            import PyKCS11
            self.session = self.pkcs11.openSession(
                self.slot,
                PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
            )
            self.session.login(self.pin)
        return self.session

    def _find_key(self, label: str):
        """Find key by label."""
        import PyKCS11
        session = self._get_session()
        template = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_LABEL, label)
        ]
        keys = session.findObjects(template)
        return keys[0] if keys else None

    def _create_key(self, label: str) -> object:
        """Create new AES-256 key in HSM."""
        import PyKCS11
        session = self._get_session()

        template = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_AES),
            (CKA_TOKEN, True),
            (CKA_LABEL, label),
            (CKA_ENCRYPT, True),
            (CKA_DECRYPT, True),
            (CKA_VALUE_LEN, 32)  # 256 bits
        ]

        key = session.generateKey(
            PyKCS11.Mechanism(CKM_AES_KEY_GEN),
            template
        )
        return key

    def get_or_create_key(self) -> object:
        """Get existing key or create new one."""
        key = self._find_key(self.key_label)
        if key is None:
            key = self._create_key(self.key_label)
        return key

    def derive_key(self, context: bytes) -> bytes:
        """
        Derive a key for a specific context.

        Uses HSM to encrypt context, producing deterministic derived key.

        Args:
            context: Context bytes (e.g., service name hash)

        Returns:
            32-byte derived key
        """
        import PyKCS11
        session = self._get_session()
        master_key = self.get_or_create_key()

        # Use context hash as IV
        iv = hashlib.sha256(context).digest()[:16]

        # Pad context to 32 bytes
        padded = context.ljust(32, b'\x00')[:32]

        # Encrypt context with master key to derive service key
        mechanism = PyKCS11.Mechanism(CKM_AES_CBC_PAD, iv)
        derived = bytes(session.encrypt(master_key, padded, mechanism))

        # Hash result to get 32-byte key
        return hashlib.sha256(derived).digest()

    def wrap_key(self, key: bytes) -> bytes:
        """Wrap (encrypt) a key using HSM master key."""
        import PyKCS11
        session = self._get_session()
        master_key = self.get_or_create_key()

        iv = os.urandom(16)
        mechanism = PyKCS11.Mechanism(CKM_AES_CBC_PAD, iv)
        encrypted = bytes(session.encrypt(master_key, key, mechanism))

        return iv + encrypted

    def unwrap_key(self, wrapped: bytes) -> bytes:
        """Unwrap (decrypt) a key using HSM master key."""
        import PyKCS11
        session = self._get_session()
        master_key = self.get_or_create_key()

        iv = wrapped[:16]
        encrypted = wrapped[16:]

        mechanism = PyKCS11.Mechanism(CKM_AES_CBC_PAD, iv)
        decrypted = bytes(session.decrypt(master_key, encrypted, mechanism))

        return decrypted

    def close(self):
        """Close HSM session."""
        if self.session:
            self.session.logout()
            self.session.closeSession()
            self.session = None


def example_usage():
    """Example of using Shield with AWS CloudHSM."""
    from shield import quick_encrypt, quick_decrypt

    # Initialize HSM provider
    hsm = CloudHSMKeyProvider(
        key_label='shield-production-key'
    )

    try:
        # Derive key for service
        service = 'myapp.example.com'
        key = hsm.derive_key(service.encode())

        # Use Shield with HSM-derived key
        plaintext = b'Secret data protected by AWS CloudHSM'
        encrypted = quick_encrypt(key, plaintext)
        decrypted = quick_decrypt(key, encrypted)

        print(f"Original: {plaintext}")
        print(f"Decrypted: {decrypted}")
        assert plaintext == decrypted
        print("Success!")

    finally:
        hsm.close()


if __name__ == '__main__':
    example_usage()
