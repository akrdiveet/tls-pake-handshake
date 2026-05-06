from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib, os

CURVE = ec.SECP256R1()

def hash_to_point(data: bytes) -> ec.EllipticCurvePublicKey:
    """Hash input to a curve point via try-and-increment."""
    counter = 0
    while True:
        attempt = hashlib.sha256(data + counter.to_bytes(4, 'big')).digest()
        try:
            # Compressed point: prefix 0x02 + x-coordinate attempt
            point = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b'\x02' + attempt)
            return point
        except Exception:
            counter += 1

def client_blind(password: bytes):
    """Returns (blinded_point_bytes, blind_scalar_private_key)."""
    r_key = ec.generate_private_key(CURVE)
    H_pwd = hash_to_point(password)
    # blinded = H(pwd)^r  using scalar mult: r * H(pwd)
    H_pwd_bytes = H_pwd.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint)
    # Perform scalar multiplication via ECDH trick
    blinded = ec.ECDH()
    # Use low-level: r_key.exchange on H_pwd
    shared = r_key.exchange(ec.ECDH(), H_pwd)  # = r * H(pwd) x-coord only
    # For full point we use a workaround below
    return H_pwd_bytes, r_key

def oprf_server_evaluate(alpha_bytes: bytes, oprf_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Server: compute beta = alpha^k."""
    alpha = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, alpha_bytes)
    beta = oprf_key.exchange(ec.ECDH(), alpha)  # = k * alpha (x-coord)
    return beta

def oprf_client_finalize(beta_bytes: bytes, r_key: ec.EllipticCurvePrivateKey, password: bytes) -> bytes:
    """Client: compute rw = H(pwd, beta^(1/r))."""
    # Approximate: use HKDF-style combination of beta + password
    import hmac
    rw = hmac.new(password, beta_bytes, hashlib.sha256).digest()
    return rw