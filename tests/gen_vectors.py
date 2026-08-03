#!/usr/bin/env python3
"""
Generate deterministic ratchet test vectors for the three ratchet families.
Uses a fixed nonce to produce reproducible output.
"""
import hashlib
import hmac as hmac_mod
import struct
import json
import base64
import sys
import os

# Deterministic inputs
ROOT_KEY = bytes([0x42] * 32)
FIXED_NONCE = bytes(range(16))   # 0x00..0x0f
PLAINTEXT = b"Hello, Shield!"


def sha256(data):
    return hashlib.sha256(data).digest()


# ===========================================================================
# Family B: Python/JS/Kotlin/Android/iOS
# chain: SHA256(key||label), step: SHA256(chain||"chain"/"message")
# frame: nonce(16) || XOR(ctr_le64||plaintext, SHA256_keystream) || HMAC[:16]
# counter is INSIDE the ciphertext (encrypted)
# ===========================================================================

def generate_keystream_B(key, nonce, length):
    ks = b""
    for i in range((length + 31) // 32):
        ks += sha256(key + nonce + struct.pack("<I", i))
    return ks[:length]


def family_b_vector():
    send_chain_init = sha256(ROOT_KEY + b"send")
    recv_chain_init = sha256(ROOT_KEY + b"recv")  # Bob's recv = Alice's send

    # Alice ratchets send chain
    new_send_chain = sha256(send_chain_init + b"chain")
    msg_key = sha256(send_chain_init + b"message")

    counter = 0
    counter_bytes = struct.pack("<Q", counter)
    data = counter_bytes + PLAINTEXT

    ks = generate_keystream_B(msg_key, FIXED_NONCE, len(data))
    ciphertext_data = bytes(p ^ k for p, k in zip(data, ks))
    mac = hmac_mod.new(msg_key, FIXED_NONCE + ciphertext_data, hashlib.sha256).digest()[:16]
    encrypted = FIXED_NONCE + ciphertext_data + mac

    # Verify round-trip
    bob_recv = send_chain_init  # Bob's recv_chain starts == SHA256(root||"send")
    _, bob_msg_key = sha256(bob_recv + b"chain"), sha256(bob_recv + b"message")
    bob_msg_key = sha256(bob_recv + b"message")
    nonce_v = encrypted[:16]
    ct_v = encrypted[16:-16]
    mac_v = encrypted[-16:]
    exp_mac = hmac_mod.new(bob_msg_key, nonce_v + ct_v, hashlib.sha256).digest()[:16]
    assert mac_v == exp_mac, "Family B: MAC mismatch"
    ks2 = generate_keystream_B(bob_msg_key, nonce_v, len(ct_v))
    dec = bytes(c ^ k for c, k in zip(ct_v, ks2))
    assert struct.unpack("<Q", dec[:8])[0] == 0
    assert dec[8:] == PLAINTEXT, "Family B: plaintext mismatch"

    return {
        "description": "Alice (initiator) encrypts first message to Bob",
        "root_key": ROOT_KEY.hex(),
        "is_initiator": True,
        "counter": counter,
        "plaintext_hex": PLAINTEXT.hex(),
        "plaintext_utf8": PLAINTEXT.decode(),
        "fixed_nonce_hex": FIXED_NONCE.hex(),
        "intermediate": {
            "send_chain_after_init": send_chain_init.hex(),
            "msg_key": msg_key.hex(),
            "new_send_chain": new_send_chain.hex(),
        },
        "ciphertext_hex": encrypted.hex(),
        "ciphertext_base64": base64.b64encode(encrypted).decode(),
        "note": "nonce is fixed for test vector reproducibility; production uses random nonce",
    }


# ===========================================================================
# Family C: Go/Java/Swift/C#/C
# chain: SHA256(key||"init_send"/"init_recv"), step: SHA256(chain||"ratchet"/"message")
# frame: ctr_le64(8) || nonce(16) || XOR(plaintext, SHA256_keystream) || HMAC[:16]
# counter is CLEARTEXT (first 8 bytes of frame)
# keystream: SHA256(msg_key||nonce||block_u32le) but generated the same way as B
# MAC: HMAC-SHA256(msg_key, ctr||nonce||ciphertext)[:16]
# ===========================================================================

def generate_keystream_C(key, nonce, length):
    """Go uses generateKeystream which is SHA256(key||nonce||block_ctr)."""
    ks = b""
    for i in range((length + 31) // 32):
        ks += sha256(key + nonce + struct.pack("<I", i))
    return ks[:length]


def family_c_vector():
    # Go initiator labels: "init_send" / "init_recv"
    send_key_init = sha256(ROOT_KEY + b"init_send")
    recv_key_init = sha256(ROOT_KEY + b"init_recv")

    # Go derives message key as SHA256(sendKey||"message"), then ratchets with SHA256(sendKey||"ratchet")
    msg_key = sha256(send_key_init + b"message")
    new_send_key = sha256(send_key_init + b"ratchet")

    counter = 0
    counter_bytes = struct.pack("<Q", counter)

    # Encrypt plaintext only (counter is cleartext in Go)
    ks = generate_keystream_C(msg_key, FIXED_NONCE, len(PLAINTEXT))
    ciphertext_data = bytes(p ^ k for p, k in zip(PLAINTEXT, ks))

    # MAC: HMAC(msg_key, ctr||nonce||ciphertext)
    mac_input = counter_bytes + FIXED_NONCE + ciphertext_data
    import hmac as _hmac
    mac = _hmac.new(msg_key, mac_input, hashlib.sha256).digest()[:16]

    # Frame: counter(8) || nonce(16) || ciphertext || mac(16)
    encrypted = counter_bytes + FIXED_NONCE + ciphertext_data + mac

    # Verify round-trip
    bob_recv = sha256(ROOT_KEY + b"init_send")  # Bob's recv starts == Alice's send
    bob_msg_key = sha256(bob_recv + b"message")
    assert bob_msg_key == msg_key

    ctr_back = struct.unpack("<Q", encrypted[:8])[0]
    nonce_v = encrypted[8:24]
    ct_v = encrypted[24:-16]
    mac_v = encrypted[-16:]
    mac_input2 = encrypted[:8] + nonce_v + ct_v
    exp_mac = _hmac.new(bob_msg_key, mac_input2, hashlib.sha256).digest()[:16]
    assert mac_v == exp_mac, f"Family C: MAC mismatch: got {mac_v.hex()} expected {exp_mac.hex()}"
    ks2 = generate_keystream_C(bob_msg_key, nonce_v, len(ct_v))
    dec = bytes(c ^ k for c, k in zip(ct_v, ks2))
    assert dec == PLAINTEXT, f"Family C: plaintext mismatch: {dec!r}"

    return {
        "description": "Alice (initiator) encrypts first message to Bob",
        "root_key": ROOT_KEY.hex(),
        "is_initiator": True,
        "counter": counter,
        "plaintext_hex": PLAINTEXT.hex(),
        "plaintext_utf8": PLAINTEXT.decode(),
        "fixed_nonce_hex": FIXED_NONCE.hex(),
        "intermediate": {
            "send_key_after_init": send_key_init.hex(),
            "msg_key": msg_key.hex(),
            "new_send_key_after_ratchet": new_send_key.hex(),
        },
        "ciphertext_hex": encrypted.hex(),
        "ciphertext_base64": base64.b64encode(encrypted).decode(),
        "frame_layout": "counter_le64(8) || nonce(16) || ciphertext(len(plaintext)) || hmac_sha256_truncated_16(16)",
        "note": "nonce is fixed for test vector reproducibility; production uses random nonce",
    }


# ===========================================================================
# Family A: Rust / WASM
# chain: HMAC-SHA256(root, "send"/"recv"), step: HMAC(chain,"chain"/"message")
# subkeys: enc_key=HMAC(msg_key,"shield-ratchet-encrypt"),
#          mac_key=HMAC(msg_key,"shield-ratchet-authenticate")
# frame: nonce(16) || XOR(ctr_le64||plaintext, HMAC_keystream) || HMAC[:16]
# counter is INSIDE the ciphertext (encrypted), keystream uses HMAC not SHA256
# ===========================================================================

def hmac_sha256(key, data):
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def family_a_vector():
    import hmac as _hmac

    # Rust: derive_chain_key uses HMAC-SHA256(root, label)
    send_chain_init = hmac_sha256(ROOT_KEY, b"send")
    recv_chain_init = hmac_sha256(ROOT_KEY, b"recv")

    # ratchet_chain: new_chain=HMAC(chain,"chain"), msg_key=HMAC(chain,"message")
    new_send_chain = hmac_sha256(send_chain_init, b"chain")
    msg_key = hmac_sha256(send_chain_init, b"message")

    # derive_msg_subkeys:
    enc_key = hmac_sha256(msg_key, b"shield-ratchet-encrypt")
    mac_key = hmac_sha256(msg_key, b"shield-ratchet-authenticate")

    counter = 0
    counter_bytes = struct.pack("<Q", counter)
    data = counter_bytes + PLAINTEXT

    # Keystream: HMAC(enc_key, nonce||block_u32le)
    num_blocks = (len(data) + 31) // 32
    ks = b""
    for i in range(num_blocks):
        block_data = FIXED_NONCE + struct.pack("<I", i)
        ks += hmac_sha256(enc_key, block_data)
    ks = ks[:len(data)]

    ciphertext_data = bytes(p ^ k for p, k in zip(data, ks))

    # MAC: HMAC(mac_key, nonce||ciphertext)
    mac = hmac_sha256(mac_key, FIXED_NONCE + ciphertext_data)[:16]

    # Frame: nonce(16) || ciphertext || mac(16)
    encrypted = FIXED_NONCE + ciphertext_data + mac

    # Verify round-trip (Bob: recv_chain_init == send_chain_init per Rust initiator logic)
    # Bob's recv_chain = HMAC(root,"send") (Bob is non-initiator, so recv_label="send")
    bob_recv = hmac_sha256(ROOT_KEY, b"send")
    assert bob_recv == send_chain_init

    bob_msg_key = hmac_sha256(bob_recv, b"message")
    assert bob_msg_key == msg_key

    bob_enc_key = hmac_sha256(bob_msg_key, b"shield-ratchet-encrypt")
    bob_mac_key = hmac_sha256(bob_msg_key, b"shield-ratchet-authenticate")

    nonce_v = encrypted[:16]
    ct_v = encrypted[16:-16]
    mac_v = encrypted[-16:]
    exp_mac = hmac_sha256(bob_mac_key, nonce_v + ct_v)[:16]
    assert mac_v == exp_mac, f"Family A: MAC mismatch: {mac_v.hex()} vs {exp_mac.hex()}"

    num_blocks2 = (len(ct_v) + 31) // 32
    ks2 = b""
    for i in range(num_blocks2):
        block_data = nonce_v + struct.pack("<I", i)
        ks2 += hmac_sha256(bob_enc_key, block_data)
    ks2 = ks2[:len(ct_v)]
    dec = bytes(c ^ k for c, k in zip(ct_v, ks2))
    assert struct.unpack("<Q", dec[:8])[0] == 0
    assert dec[8:] == PLAINTEXT, f"Family A: plaintext mismatch: {dec!r}"

    return {
        "description": "Alice (initiator) encrypts first message to Bob",
        "root_key": ROOT_KEY.hex(),
        "is_initiator": True,
        "counter": counter,
        "plaintext_hex": PLAINTEXT.hex(),
        "plaintext_utf8": PLAINTEXT.decode(),
        "fixed_nonce_hex": FIXED_NONCE.hex(),
        "intermediate": {
            "send_chain_after_init": send_chain_init.hex(),
            "msg_key": msg_key.hex(),
            "new_send_chain": new_send_chain.hex(),
            "enc_key": enc_key.hex(),
            "mac_key": mac_key.hex(),
        },
        "ciphertext_hex": encrypted.hex(),
        "ciphertext_base64": base64.b64encode(encrypted).decode(),
        "frame_layout": "nonce(16) || HMAC_keystream_XOR(ctr_le64||plaintext) || hmac_sha256_truncated_16(16)",
        "note": "nonce is fixed for test vector reproducibility; production uses random nonce",
    }


if __name__ == "__main__":
    vectors = {
        "schema_version": "1",
        "note": "Deterministic test vectors for each Shield ratchet family. Fixed nonce is used for reproducibility only; production code uses random nonces.",
        "families": {
            "A": {
                "bindings": ["rust", "wasm"],
                "description": "HMAC chain, separate enc/mac subkeys, counter encrypted inside ciphertext",
                "chain_algorithm": "HMAC-SHA256(root, label)",
                "chain_step": "new_chain=HMAC(chain,'chain'), msg_key=HMAC(chain,'message')",
                "subkeys": "enc_key=HMAC(msg_key,'shield-ratchet-encrypt'), mac_key=HMAC(msg_key,'shield-ratchet-authenticate')",
                "keystream": "HMAC(enc_key, nonce||block_ctr_le32)",
                "mac_input": "HMAC(mac_key, nonce||ciphertext)",
                "counter_placement": "encrypted (first 8 bytes of XOR input, little-endian uint64)",
                "frame_layout": "nonce(16) || ciphertext(8+len(plaintext)) || mac_truncated_16(16)",
                "init_labels": {"initiator_send": "send", "initiator_recv": "recv"},
                "vectors": [family_a_vector()],
            },
            "B": {
                "bindings": ["python", "javascript", "kotlin", "android", "ios"],
                "description": "SHA256 chain, single key, counter encrypted inside ciphertext",
                "chain_algorithm": "SHA256(root || label)",
                "chain_step": "new_chain=SHA256(chain||'chain'), msg_key=SHA256(chain||'message')",
                "keystream": "SHA256(msg_key || nonce || block_ctr_le32)",
                "mac_input": "HMAC-SHA256(msg_key, nonce||ciphertext)[:16]",
                "counter_placement": "encrypted (first 8 bytes of XOR input, little-endian uint64)",
                "frame_layout": "nonce(16) || ciphertext(8+len(plaintext)) || mac_truncated_16(16)",
                "init_labels": {"initiator_send": "send", "initiator_recv": "recv"},
                "vectors": [family_b_vector()],
            },
            "C": {
                "bindings": ["go", "java", "swift", "csharp", "c"],
                "description": "SHA256 chain, single key, counter in cleartext prefix",
                "chain_algorithm": "SHA256(root || label)",
                "chain_step": "msg_key=SHA256(chain||'message'), new_chain=SHA256(chain||'ratchet')",
                "keystream": "SHA256(msg_key || nonce || block_ctr_le32)",
                "mac_input": "HMAC-SHA256(msg_key, ctr_le64||nonce||ciphertext)[:16]",
                "counter_placement": "cleartext_prefix_8_bytes (little-endian uint64)",
                "frame_layout": "counter_le64(8) || nonce(16) || ciphertext(len(plaintext)) || mac_truncated_16(16)",
                "init_labels": {"initiator_send": "init_send", "initiator_recv": "init_recv"},
                "vectors": [family_c_vector()],
            },
        },
        "cross_family_compatibility": "none — families A, B, C are mutually incompatible",
        "within_family_interop": "supported — all bindings in the same family share a wire format",
        "migration": "Full realignment to Family A is tracked in backend-064",
    }

    out_path = os.path.join(os.path.dirname(__file__), "ratchet_vectors.json")
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Written: {out_path}")

    # Also emit separate per-family files as the task checklist mentions
    for family in ["A", "B", "C"]:
        single = {
            "schema_version": "1",
            "family": family,
            **vectors["families"][family],
        }
        fname = os.path.join(os.path.dirname(__file__), f"ratchet_vectors_family_{family.lower()}.json")
        with open(fname, "w") as f:
            json.dump(single, f, indent=2)
        print(f"Written: {fname}")

    print("All vectors generated and verified.")
