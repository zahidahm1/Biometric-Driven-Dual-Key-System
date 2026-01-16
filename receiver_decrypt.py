#!/usr/bin/env python3
"""
receiver_decrypt.py

Receiver-side decryption script for:
 - AES-256-GCM encrypted message package
 - Biometric-wrapped AES session key

Modes:
 - sensor : uses a connected fingerprint module (R305/ZFM-20 via pyfingerprint)
 - sim    : simulation mode (useful for dev/tests; uses a user-provided string to simulate template)

NOTES:
 - This is a prototype/PoC. It uses the fingerprint module's exported characteristics (template bytes)
   and hashes them; this is NOT a full fuzzy-extractor. If the sensor returns different template bytes
   across captures, enrollment/verification may fail. For production, implement a proper fuzzy-extractor
   or prefer platform secure biometric bound keys (Keystore / Secure Enclave).
"""

import json
import argparse
import base64
import binascii
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Optional: try to import pyfingerprint; if not present, sensor mode will fail
try:
    from pyfingerprint.pyfingerprint import PyFingerprint
    PYPRESENT = True
except Exception:
    PYPRESENT = False

def b64_to_bytes(s):
    return base64.b64decode(s)

def hex_to_bytes(s):
    # accepts "hex:..." or raw hex
    if s.startswith("hex:"):
        s = s[4:]
    return binascii.unhexlify(s)

def derive_key_from_identity(identity_hash: bytes, server_secret: bytes, msg_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=server_secret,
        info=msg_id.encode(),
        backend=default_backend()
    )
    return hkdf.derive(identity_hash)

def aesgcm_decrypt_with_tag(nonce, ciphertext, tag, key, aad=b''):
    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    return aesgcm.decrypt(nonce, combined, aad)

def aesgcm_decrypt_wrapped_key(derived_key, wrap_nonce, wrapped_session_key):
    aesgcm = AESGCM(derived_key)
    # wrapped_session_key is ciphertext+tag (module encrypt returned full output)
    # many implementations already store ciphertext+tag together. Here we expect wrapped_session_key includes tag at end.
    # We'll attempt decrypt directly; if the wrapped_session_key length indicates tag present, do direct call.
    try:
        return aesgcm.decrypt(wrap_nonce, wrapped_session_key, None)
    except Exception as e:
        raise

# ---------- Fingerprint functions ----------
def capture_template_from_sensor(serial_port='/dev/ttyUSB0', baud=57600, timeout=20):
    if not PYPRESENT:
        raise RuntimeError("pyfingerprint not installed or import failed. Install pyfingerprint for sensor mode.")
    f = PyFingerprint(serial_port, baud, 0xFFFFFFFF, 0x00000000)
    if not f.verifyPassword():
        raise RuntimeError("Could not verify fingerprint sensor password")
    print("Sensor ready: place finger on sensor...")
    # wait loop
    import time
    t0 = time.time()
    while not f.readImage():
        time.sleep(0.5)
        if time.time() - t0 > timeout:
            raise TimeoutError("No finger detected within timeout")
    f.convertImage(0x01)
    # download characteristics from buffer 1
    char_list = f.downloadCharacteristics(0x01)  # list of ints
    # Produce stable bytes representation
    template_bytes = bytes(char_list)
    return template_bytes

def enroll_simulated_template(sim_data: str):
    # deterministic pseudo-template for simulation (not secure)
    return sim_data.encode('utf-8')

# ---------- Main flow ----------
def run_decrypt(args):
    # Load encrypted message package
    pkg = json.load(open(args.package, 'r'))
    msg_id = pkg['msgID']
    ciphertext = b64_to_bytes(pkg['ciphertext_b64'])
    nonce = b64_to_bytes(pkg['nonce_b64'])
    tag = b64_to_bytes(pkg['tag_b64'])

    # Load recipient wrap info
    wrap = json.load(open(args.wrap, 'r'))
    salt = hex_to_bytes(wrap['salt_hex'])
    wrap_nonce = hex_to_bytes(wrap['wrap_nonce_hex'])
    wrapped_session_key = hex_to_bytes(wrap['wrapped_session_key_hex'])

    # server_secret provided as hex string or file content
    server_secret = None
    if args.server_secret.startswith('hex:') or all(c in '0123456789abcdefABCDEF' for c in args.server_secret):
        server_secret = hex_to_bytes(args.server_secret)
    elif args.server_secret.endswith('.bin') or args.server_secret.endswith('.txt'):
        server_secret = open(args.server_secret, 'rb').read()
    else:
        # fallback interpret as hex
        server_secret = hex_to_bytes(args.server_secret)

    # Capture biometric template
    if args.mode == 'sensor':
        print("Using fingerprint sensor (serial port:", args.serial_port, ")")
        template_bytes = capture_template_from_sensor(serial_port=args.serial_port, baud=args.baud, timeout=args.timeout)
    else:
        print("SIMULATION MODE: using provided simulation data")
        template_bytes = enroll_simulated_template(args.sim_data)

    # Compute identity hash (same as sender)
    h = hashlib.sha256()
    h.update(template_bytes)
    h.update(salt)
    identity_hash = h.digest()

    # Derive key with HKDF (must match sender's HKDF params)
    derived_key = derive_key_from_identity(identity_hash, server_secret, msg_id)

    # Unwrap session key (AES-GCM decrypt)
    try:
        session_key = aesgcm_decrypt_wrapped_key(derived_key, wrap_nonce, wrapped_session_key)
    except Exception as e:
        print("Failed to unwrap session key. Possible causes:")
        print(" - Wrong biometric capture (template mismatch)")
        print(" - Wrong server_secret or msgID mismatch")
        print(" - Corrupted wrapped key")
        raise

    print("Successfully unwrapped session key (length = {} bytes)".format(len(session_key)))

    # Decrypt message
    try:
        plaintext = aesgcm_decrypt_with_tag(nonce, ciphertext, tag, session_key, aad=msg_id.encode())
    except Exception as e:
        print("Decrypt failed. Possible wrong session_key or corrupted ciphertext.")
        raise

    print("\n===== DECRYPTED MESSAGE =====")
    print(plaintext.decode('utf-8', errors='replace'))
    print("=============================\n")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Receiver-side decryptor (biometric-driven wrap)")
    parser.add_argument('--package', required=True, help="Encrypted message JSON (msgID, ciphertext_b64, nonce_b64, tag_b64)")
    parser.add_argument('--wrap', required=True, help="Recipient wrap JSON (salt_hex, wrap_nonce_hex, wrapped_session_key_hex)")
    parser.add_argument('--server-secret', required=True, help="Server secret (hex:...) or path to raw file")
    parser.add_argument('--mode', choices=['sensor','sim'], default='sim', help="sensor to use fingerprint module; sim to use simulated data")
    parser.add_argument('--sim-data', help="Simulated biometric data (string) for --mode sim", default="fingerprint_simulated_B")
    parser.add_argument('--serial-port', default='/dev/ttyUSB0', help="Serial port for fingerprint sensor")
    parser.add_argument('--baud', type=int, default=57600, help="Baud rate for fingerprint sensor")
    parser.add_argument('--timeout', type=int, default=20, help="Seconds to wait for finger press")
    args = parser.parse_args()
    run_decrypt(args)

if __name__ == '__main__':
    main()
