# Biometric-Driven Dual Key System — Sender-Side Prototype

import hashlib
import secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

def generate_aes_session_key():
    return secrets.token_bytes(32)

def generate_salt():
    
    return secrets.token_bytes(16)

def hash_biometric_data(biometric_data, salt):
    
    h = hashlib.sha256()
    h.update(biometric_data)
    h.update(salt)
    return h.digest()

def derive_user_key(identity_hash, server_secret, msg_id):
    # Derive user-specific key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=server_secret,
        info=msg_id,
        backend=default_backend(),
    )
    return hkdf.derive(identity_hash)

def encrypt_session_key(derived_key, session_key):
    # Encrypt session key using AES-GCM.
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, session_key, None)
    return nonce, ciphertext

def main():
    print("Biometric-Driven Dual Key System — Sender Prototype\n")
    print("Executing Key Derivation & Encryption Phase\n")

    
    session_key = generate_aes_session_key()
    msg_id = b"msg-123"
    server_secret = secrets.token_bytes(32)

    recipients = {
        "user_A": b"fingerprintA_simulated",
        "user_B": b"fingerprintB_simulated",
        "user_C": b"fingerprintC_simulated"
    }

    for user, biometric_data in recipients.items():
        salt = generate_salt()
        identity_hash = hash_biometric_data(biometric_data, salt)
        derived_key = derive_user_key(identity_hash, server_secret, msg_id)
        nonce, ciphertext = encrypt_session_key(derived_key, session_key)

        print(f"Recipient: {user}")
        print(f"  Salt (preview):        {salt.hex()[:20]}...")
        print(f"  Identity hash (SHA-256): {identity_hash.hex()[:20]}...")
        print(f"  Derived key (HKDF):    {derived_key.hex()[:20]}...")
        print(f"  Nonce:                 {nonce.hex()}")
        print(f"  Ciphertext length:     {len(ciphertext)} bytes")
        print(f"  Encrypted session key (preview): {ciphertext.hex()[:20]}...\n")

    print("(Key Derivation & Encryption Phase) executed successfully.\n")
    

if __name__ == "__main__":
    main()
