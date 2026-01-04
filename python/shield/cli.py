#!/usr/bin/env python3
"""
Shield CLI - Command-line interface for Shield encryption.

Usage:
    shield encrypt <file> [-o OUTPUT] [-p PASSWORD]
    shield decrypt <file> [-o OUTPUT] [-p PASSWORD]
    shield keygen [--length LENGTH]
    shield totp-setup [--account ACCOUNT] [--issuer ISSUER]
    shield totp-code <secret>

Examples:
    # Encrypt a file
    shield encrypt secret.txt -o secret.enc

    # Decrypt a file
    shield decrypt secret.enc -o secret.txt

    # Generate a random key (hex)
    shield keygen

    # Set up TOTP for 2FA
    shield totp-setup --account user@example.com

    # Generate TOTP code
    shield totp-code JBSWY3DPEHPK3PXP
"""

import argparse
import sys
import os
import getpass
from typing import Optional

from shield.core import Shield
from shield.stream import StreamCipher
from shield.totp import TOTP


def get_password(prompt: str = "Password: ", confirm: bool = False) -> str:
    """Get password from user with optional confirmation."""
    password = getpass.getpass(prompt)
    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            print("Error: Passwords do not match", file=sys.stderr)
            sys.exit(1)
    return password


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypt a file."""
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 1

    password = args.password or get_password(confirm=True)
    output = args.output or args.file + ".enc"

    # Use file path as salt for deterministic key derivation
    salt = os.path.basename(args.file).encode()
    cipher = StreamCipher.from_password(password, salt)

    try:
        cipher.encrypt_file(args.file, output)
        print(f"Encrypted: {args.file} -> {output}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt a file."""
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 1

    password = args.password or get_password()

    # Determine output filename
    if args.output:
        output = args.output
    elif args.file.endswith(".enc"):
        output = args.file[:-4]
    else:
        output = args.file + ".dec"

    # Use original filename (without .enc) as salt
    original_name = os.path.basename(output)
    salt = original_name.encode()
    cipher = StreamCipher.from_password(password, salt)

    try:
        cipher.decrypt_file(args.file, output)
        print(f"Decrypted: {args.file} -> {output}")
        return 0
    except ValueError as e:
        print(f"Error: Authentication failed - wrong password or corrupted file", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a random key."""
    length = args.length or 32
    key = os.urandom(length)
    print(key.hex())
    return 0


def cmd_totp_setup(args: argparse.Namespace) -> int:
    """Set up TOTP for 2FA."""
    secret = TOTP.generate_secret()
    totp = TOTP(secret)

    account = args.account or "user@example.com"
    issuer = args.issuer or "Shield"

    secret_b32 = TOTP.secret_to_base32(secret)
    uri = totp.provisioning_uri(account, issuer)

    print("TOTP Secret (Base32):", secret_b32)
    print()
    print("QR Code URI:", uri)
    print()
    print("Add this secret to your authenticator app (Google Authenticator, Authy, etc.)")
    print()
    print("Current code:", totp.generate())

    return 0


def cmd_totp_code(args: argparse.Namespace) -> int:
    """Generate TOTP code from secret."""
    try:
        secret = TOTP.secret_from_base32(args.secret)
        totp = TOTP(secret)
        print(totp.generate())
        return 0
    except Exception as e:
        print(f"Error: Invalid secret - {e}", file=sys.stderr)
        return 1


def main(argv: Optional[list] = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="shield",
        description="Shield - EXPTIME-Secure Encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version="shield-crypto 0.1.0"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("file", help="File to encrypt")
    encrypt_parser.add_argument("-o", "--output", help="Output file")
    encrypt_parser.add_argument("-p", "--password", help="Password (insecure, prefer prompt)")

    # decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("file", help="File to decrypt")
    decrypt_parser.add_argument("-o", "--output", help="Output file")
    decrypt_parser.add_argument("-p", "--password", help="Password (insecure, prefer prompt)")

    # keygen command
    keygen_parser = subparsers.add_parser("keygen", help="Generate random key")
    keygen_parser.add_argument("--length", type=int, default=32, help="Key length in bytes")

    # totp-setup command
    totp_setup_parser = subparsers.add_parser("totp-setup", help="Set up TOTP 2FA")
    totp_setup_parser.add_argument("--account", help="Account identifier")
    totp_setup_parser.add_argument("--issuer", help="Service name")

    # totp-code command
    totp_code_parser = subparsers.add_parser("totp-code", help="Generate TOTP code")
    totp_code_parser.add_argument("secret", help="Base32 secret")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "keygen": cmd_keygen,
        "totp-setup": cmd_totp_setup,
        "totp-code": cmd_totp_code,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
