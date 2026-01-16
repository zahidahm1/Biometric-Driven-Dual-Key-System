#!/usr/bin/env python3
"""
AES-256-GCM Encryption Prototype
--------------------------------
Final Year Project – Biometric Driven Dual Key Encryption

This script:
1. Generates a random 256-bit AES session key (K_sess).
2. Creates a unique message ID (msgID).
3. Encrypts the given message using AES-256-GCM with K_sess.
4. Outputs ciphertext, nonce, tag, and msgID in Base64 format.
"""

import os
import base64
import uuid
import json
import argparse

# ------------------- Utility Functions -------------------
def b64(x: bytes) -> str:
    """Return Base64 encoded string."""
    return base64.b64encode(x).decode('utf-8')


def generate_k_sess() -> bytes:
    """Generate random 256-bit AES session key."""
    return os.urandom(32)


def generate_msg_id() -> str:
    """Generate unique message ID using UUID4."""
    return str(uuid.uuid4())


# ------------------- AES Encryption -------------------
def encrypt_with_cryptography(key: bytes, plaintext: bytes, aad: bytes):
    """Encrypt using cryptography library (AES-256-GCM)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    tag = ct_and_tag[-16:]
    ciphertext = ct_and_tag[:-16]
    return nonce, ciphertext, tag


def encrypt_with_pycryptodome(key: bytes, plaintext: bytes, aad: bytes):
    """Encrypt using pycryptodome library (AES-256-GCM)."""
    from Crypto.Cipher import AES
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag


def encrypt_message(key: bytes, plaintext: str, msg_id: str):
    """Encrypts a plaintext message using AES-GCM."""
    plaintext_bytes = plaintext.encode('utf-8')
    aad = msg_id.encode('utf-8')

    try:
        nonce, ciphertext, tag = encrypt_with_cryptography(key, plaintext_bytes, aad)
        backend = 'cryptography'
    except Exception as e1:
        try:
            nonce, ciphertext, tag = encrypt_with_pycryptodome(key, plaintext_bytes, aad)
            backend = 'pycryptodome'
        except Exception as e2:
            return {
                'backend': None,
                'error': f"{e1} | {e2}",
                'note': "Install `cryptography` or `pycryptodome` to perform AES-GCM encryption."
            }

    return {
        'backend': backend,
        'key_b64': b64(key),
        'nonce_b64': b64(nonce),
        'ciphertext_b64': b64(ciphertext),
        'tag_b64': b64(tag),
        'msg_id': msg_id
    }


# ------------------- Main Script -------------------
def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM Encryption Prototype")
    parser.add_argument(
        "-m", "--message",
        required=True,
        help="The message you want to encrypt"
    )
    args = parser.parse_args()

    # Generate AES session key & message ID
    K_sess = generate_k_sess()
    msgID = generate_msg_id()

    # Perform encryption
    result = encrypt_message(K_sess, args.message, msgID)

    print("\n=== AES-256-GCM Encryption Output ===")
    print("Used backend:", result.get('backend', 'None'))
    print("Message ID:", result.get('msg_id'))
    print("Session Key (Base64):", result.get('key_b64'))
    print("Nonce (Base64):", result.get('nonce_b64'))
    print("Ciphertext (Base64):", result.get('ciphertext_b64'))
    print("Auth Tag (Base64):", result.get('tag_b64'))

    # JSON Output Example
    package = {
        'msgID': result.get('msg_id'),
        'ciphertext_b64': result.get('ciphertext_b64'),
        'nonce_b64': result.get('nonce_b64'),
        'tag_b64': result.get('tag_b64')
    }

    print("\nEncrypted Package (JSON):")
    print(json.dumps(package, indent=2))

    print("\n⚠️ Note: Keep K_sess secret — it will be wrapped per user in your main project.")


if __name__ == "__main__":
    main()
