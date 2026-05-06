from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Returns nonce + ciphertext."""
    nonce = os.urandom(12)  # 96-bit random nonce
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct

def decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Expects nonce prepended to ciphertext."""
    nonce, ct = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)