#!/usr/bin/env python3
"""
Live demo: two strangers exchange a quantum-safe encrypted message.

Run:  python python/examples/pq_hybrid_demo.py

Story: Alice wants to send Bob a secret. They have NEVER shared a password or key.
An eavesdropper ("Eve") records everything on the wire. Even if Eve keeps the
recording until quantum computers exist, she still can't read the message.
"""

from shield import Shield
from shield.pqhybrid import HybridPrivateKey, HybridPublicKey, initiate


def line(c="-"):
    print(c * 64)


def main():
    line("=")
    print(" Shield post-quantum hybrid key exchange — live demo")
    line("=")

    # --- Step 1: Bob publishes his public key (his "quantum-safe address") -----
    print("\n[1] Bob generates a keypair and publishes his PUBLIC key.")
    bob = HybridPrivateKey.generate()
    bob_public_bytes = bob.public_key().to_bytes()
    print(f"    Bob's public key is {len(bob_public_bytes)} bytes (safe to share with anyone).")
    print(f"    It contains TWO public keys: classical X25519 + quantum-safe ML-KEM-768.")

    # --- Step 2: Alice derives a shared key and encrypts a message ------------
    print("\n[2] Alice takes Bob's public key and runs the hybrid handshake.")
    handshake, alice_key = initiate(HybridPublicKey.from_bytes(bob_public_bytes))
    secret_message = b"Bob - the wire transfer is approved. Keep this between us."
    ciphertext = Shield.with_key(alice_key).encrypt(secret_message)
    print(f"    Alice's derived shared key : {alice_key.hex()}")
    print(f"    Handshake to send to Bob   : {len(handshake)} bytes")
    print(f"    Encrypted message          : {len(ciphertext)} bytes")

    # --- What an eavesdropper sees --------------------------------------------
    print("\n[*] On the wire, Eve only sees these opaque blobs:")
    print(f"    handshake  (first 16B): {handshake[:16].hex()}...")
    print(f"    ciphertext (first 16B): {ciphertext[:16].hex()}...")
    print("    Eve has no private key, so she learns nothing — now OR after quantum.")

    # --- Step 3: Bob recovers the same key and decrypts -----------------------
    print("\n[3] Bob receives the handshake + ciphertext and recovers the key.")
    bob_key = bob.accept(handshake)
    print(f"    Bob's derived shared key   : {bob_key.hex()}")
    print(f"    Keys match                 : {alice_key == bob_key}")

    plaintext = Shield.with_key(bob_key).decrypt(ciphertext)
    line()
    print(f"    Bob decrypts: {plaintext.decode()}")
    line()

    # --- Why it's "hybrid" ----------------------------------------------------
    print("\n[i] Why HYBRID (two algorithms)?")
    print("    The shared key mixes BOTH a classical (X25519) and a quantum-safe")
    print("    (ML-KEM-768) exchange. An attacker must break BOTH to win:")
    print("      - if a quantum computer breaks X25519  -> ML-KEM still protects you")
    print("      - if a flaw is ever found in ML-KEM    -> X25519 still protects you")
    print("\nDone. Strangers, no shared secret, eavesdropped wire, still safe. ✔")


if __name__ == "__main__":
    main()
