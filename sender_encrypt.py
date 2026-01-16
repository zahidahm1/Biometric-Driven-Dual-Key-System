#!/usr/bin/env python3
"""
FINAL SENDER-SIDE SCRIPT
-------------------------
AES-256-GCM Encryption + Biometric Dual Key Wrapping

✔ Encrypts plaintext message using AES-256-GCM
✔ Generates msgID
✔ Hashes biometric + salt
✔ Derives per-user keys (HKDF: identity_hash + server_secret + msgID)
✔ Wraps session key for each recipient
✔ SAVES OUTPUT TO JSON FILES (required by receiver)

OUTPUT FILES:
 - encrypted/encrypted_message.json
 - encrypted/<recipient>_wrap.json
"""

import os
import base64
import uuid
import json
import argparse
import hashlib
import secrets

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ---------------------- Utility ----------------------
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')


def generate_k_sess():
    return os.urandom(32)


def generate_msg_id():
    return str(uuid.uuid4())


# ---------------------- Message Encryption ----------------------
def encrypt_message(key: bytes, plaintext: str, msg_id: str):
    plaintext_bytes = plaintext.encode('utf-8')
    aad = msg_id.encode('utf-8')

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ct_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad)
    tag = ct_and_tag[-16:]
    ciphertext = ct_and_tag[:-16]

    return nonce, ciphertext, tag


# ---------------------- Biometric Key System ----------------------
def generate_salt():
    return secrets.token_bytes(16)


def hash_biometric(biometric_data, salt):
    h = hashlib.sha256()
    h.update(biometric_data)
    h.update(salt)
    return h.digest()


def derive_user_key(identity_hash, server_secret, msg_id):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=server_secret,
        info=msg_id.encode(),
        backend=default_backend(),
    )
    return hkdf.derive(identity_hash)


def encrypt_session_key(derived_key, session_key):
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(12)
    wrapped = aesgcm.encrypt(nonce, session_key, None)
    return nonce, wrapped


# ---------------------- MAIN ----------------------
def main():
    parser = argparse.ArgumentParser(description="AES + Biometric Dual Key Sender")
    parser.add_argument(
        "-m", "--message",
        required=True,
        help="Message to encrypt"
    )
    args = parser.parse_args()
    message = args.message

    # Create output directory
    os.makedirs("encrypted", exist_ok=True)

    print("\n===============================")
    print("     ENCRYPTING MESSAGE")
    print("===============================\n")

    session_key = generate_k_sess()
    msgID = generate_msg_id()

    nonce, ciphertext, tag = encrypt_message(session_key, message, msgID)

    encrypted_package = {
        "msgID": msgID,
        "ciphertext_b64": b64(ciphertext),
        "nonce_b64": b64(nonce),
        "tag_b64": b64(tag)
    }

    # SAVE encrypted message
    with open("encrypted/encrypted_message.json", "w") as f:
        json.dump(encrypted_package, f, indent=2)

    print("✔ Saved: encrypted/encrypted_message.json")

    # Generate server_secret (must be given to receiver)
    server_secret = secrets.token_bytes(32)

    print("\n===============================")
    print("   GENERATING WRAPPED KEYS")
    print("===============================\n")

    recipients = {
        "user_A": b"fingerprint_simulated_A",
        "user_B": b"fingerprint_simulated_B",
        "user_C": b"fingerprint_simulated_C"
    }

    for user, biometric_data in recipients.items():

        salt = generate_salt()
        identity_hash = hash_biometric(biometric_data, salt)
        derived_key = derive_user_key(identity_hash, server_secret, msgID)

        wrap_nonce, wrapped_key = encrypt_session_key(derived_key, session_key)

        wrap_json = {
            "user": user,
            "msgID": msgID,
            "server_secret_hex": server_secret.hex(),
            "salt_hex": salt.hex(),
            "identity_hash_hex": identity_hash.hex(),
            "wrap_nonce_hex": wrap_nonce.hex(),
            "wrapped_session_key_hex": wrapped_key.hex(),
        }

        # Write file
        out_path = f"encrypted/{user}_wrap.json"
        with open(out_path, "w") as f:
            json.dump(wrap_json, f, indent=2)

        print(f"✔ Saved: {out_path}")

    print("\n🎉 ALL DONE!")
    print("Sender output is ready for your receiver.")
    print("Use the printed server_secret_hex inside each wrap file.\n")


if __name__ == "__main__":
    main()
