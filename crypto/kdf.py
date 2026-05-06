from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes
import hashlib, hmac

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    h = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return h.derive(prk)

def derive_keys(shared_secret: bytes, transcript_hash: bytes):
    """Derive handshake and application traffic keys."""
    salt = b'\x00' * 32
    early_secret = hkdf_extract(salt, b'\x00' * 32)
    hs_secret = hkdf_extract(
        hkdf_expand(early_secret, b"derived", 32),
        shared_secret
    )
    client_hs_key = hkdf_expand(hs_secret, b"client handshake traffic secret" + transcript_hash, 32)
    server_hs_key = hkdf_expand(hs_secret, b"server handshake traffic secret" + transcript_hash, 32)
    master_secret = hkdf_extract(
        hkdf_expand(hs_secret, b"derived", 32),
        b'\x00' * 32
    )
    client_app_key = hkdf_expand(master_secret, b"client application traffic secret" + transcript_hash, 32)
    server_app_key = hkdf_expand(master_secret, b"server application traffic secret" + transcript_hash, 32)
    return {
        "client_hs_key": client_hs_key,
        "server_hs_key": server_hs_key,
        "client_app_key": client_app_key,
        "server_app_key": server_app_key
    }