"""
Shield + HashiCorp Vault Integration Example

This example shows how to use HashiCorp Vault's Transit secrets engine
to protect Shield encryption keys.

Prerequisites:
    pip install hvac shield-crypto

Vault Setup:
    vault secrets enable transit
    vault write transit/keys/shield-key type=aes256-gcm96
"""

import os
import base64
import hvac


class VaultKeyProvider:
    """
    Key provider using HashiCorp Vault Transit secrets engine.

    The master key is stored in Vault and never exposed. Vault wraps/unwraps
    the key material used by Shield.
    """

    def __init__(self, url: str, token: str, key_name: str = 'shield-key',
                 mount_point: str = 'transit'):
        """
        Initialize Vault key provider.

        Args:
            url: Vault server URL
            token: Vault authentication token
            key_name: Name of the Transit key
            mount_point: Transit secrets engine mount point
        """
        self.client = hvac.Client(url=url, token=token)
        self.key_name = key_name
        self.mount_point = mount_point

        # Verify connection and key exists
        if not self.client.is_authenticated():
            raise ValueError("Vault authentication failed")

        # Create key if it doesn't exist
        try:
            self.client.secrets.transit.read_key(
                name=key_name,
                mount_point=mount_point
            )
        except hvac.exceptions.InvalidPath:
            self.client.secrets.transit.create_key(
                name=key_name,
                key_type='aes256-gcm96',
                mount_point=mount_point
            )

    def derive_key(self, context: bytes) -> bytes:
        """
        Derive a key using Vault's key derivation.

        Args:
            context: Context for key derivation (e.g., service name)

        Returns:
            32-byte derived key
        """
        # Use Vault to derive a data key
        response = self.client.secrets.transit.generate_data_key(
            name=self.key_name,
            key_type='plaintext',
            context=base64.b64encode(context).decode(),
            mount_point=self.mount_point
        )

        # Return the plaintext key (Vault also returns ciphertext for storage)
        plaintext_key = base64.b64decode(response['data']['plaintext'])
        return plaintext_key[:32]  # Ensure 32 bytes

    def wrap_key(self, key: bytes) -> bytes:
        """
        Wrap a key using Vault.

        Args:
            key: Key material to wrap

        Returns:
            Wrapped (encrypted) key
        """
        response = self.client.secrets.transit.encrypt_data(
            name=self.key_name,
            plaintext=base64.b64encode(key).decode(),
            mount_point=self.mount_point
        )
        return response['data']['ciphertext'].encode()

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        """
        Unwrap a key using Vault.

        Args:
            wrapped_key: Wrapped key material

        Returns:
            Unwrapped key
        """
        response = self.client.secrets.transit.decrypt_data(
            name=self.key_name,
            ciphertext=wrapped_key.decode(),
            mount_point=self.mount_point
        )
        return base64.b64decode(response['data']['plaintext'])


def example_usage():
    """Example of using Shield with Vault."""
    from shield import Shield

    # Initialize Vault provider
    vault = VaultKeyProvider(
        url=os.environ.get('VAULT_ADDR', 'http://localhost:8200'),
        token=os.environ.get('VAULT_TOKEN'),
        key_name='shield-production-key'
    )

    # Derive key for service
    service = 'myapp.example.com'
    key = vault.derive_key(service.encode())

    # Use Shield with derived key
    # Note: This bypasses password-based key derivation
    from shield import quick_encrypt, quick_decrypt

    plaintext = b'Secret data protected by Vault HSM'
    encrypted = quick_encrypt(key, plaintext)
    decrypted = quick_decrypt(key, encrypted)

    print(f"Original: {plaintext}")
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Decrypted: {decrypted}")
    assert plaintext == decrypted


if __name__ == '__main__':
    example_usage()
