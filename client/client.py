import socket, json, os, hashlib, hmac, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crypto.signature import verify, load_cert
from crypto.aes_gcm import encrypt, decrypt
from crypto.kdf import derive_keys
from crypto.oprf import oprf_client_finalize

def send_msg(conn, data: bytes):
    length = len(data).to_bytes(4, 'big')
    conn.sendall(length + data)

def recv_msg(conn) -> bytes:
    raw_len = conn.recv(4)
    if not raw_len:
        return b""
    length = int.from_bytes(raw_len, 'big')
    data = b""
    while len(data) < length:
        data += conn.recv(length - len(data))
    return data

def register(username: str, password: str):
    password_bytes = password.encode()
    from crypto.oprf import hash_to_point
    from cryptography.hazmat.primitives import serialization as ser

    r_key = ec.generate_private_key(ec.SECP256R1())
    H_pwd = hash_to_point(password_bytes)
    H_pwd_bytes = H_pwd.public_bytes(
        ser.Encoding.X962, ser.PublicFormat.CompressedPoint)
    alpha = r_key.exchange(ec.ECDH(), H_pwd)  # blinded

    with socket.create_connection(("127.0.0.1", 8443)) as conn:
        send_msg(conn, json.dumps({
            "username": username,
            "intent": "register",
            "alpha": H_pwd_bytes.hex()  # simplified: send H(pwd) as alpha
        }).encode())

        resp = json.loads(recv_msg(conn))
        beta = bytes.fromhex(resp["beta"])
        rw = oprf_client_finalize(beta, r_key, password_bytes)

        # Generate client long-term keypair, encrypt with rw
        from crypto.aes_gcm import encrypt as ae_enc
        client_lt_key = ec.generate_private_key(ec.SECP256R1())
        client_lt_key_bytes = client_lt_key.private_bytes(
            ser.Encoding.PEM,
            ser.PrivateFormat.TraditionalOpenSSL,
            ser.NoEncryption())
        envelope = ae_enc(rw[:32], client_lt_key_bytes)

        send_msg(conn, json.dumps({"envelope": envelope.hex()}).encode())
        result = json.loads(recv_msg(conn))
        print(f"[Client] Registration: {result}")

def handshake_and_chat(username: str, password: str):
    password_bytes = password.encode()
    ca_cert = load_cert("ca/ca_cert.pem")

    from crypto.oprf import hash_to_point
    from cryptography.hazmat.primitives import serialization as ser

    r_key = ec.generate_private_key(ec.SECP256R1())
    H_pwd = hash_to_point(password_bytes)
    H_pwd_bytes = H_pwd.public_bytes(
        ser.Encoding.X962, ser.PublicFormat.CompressedPoint)

    client_hello = f"ClientHello:{username}"
    transcript = client_hello.encode()

    with socket.create_connection(("127.0.0.1", 8443)) as conn:
        send_msg(conn, json.dumps({
            "username": username,
            "intent": "handshake",
            "client_hello": client_hello,
            "alpha": H_pwd_bytes.hex()
        }).encode())

        # Receive server response
        resp = json.loads(recv_msg(conn))
        if "error" in resp:
            print(f"[Client] Error: {resp['error']}")
            return

        cert_bytes = bytes.fromhex(resp["cert"])
        beta = bytes.fromhex(resp["beta"])
        eph_pub_bytes = bytes.fromhex(resp["eph_pub"])
        sig = bytes.fromhex(resp["sig"])
        envelope = bytes.fromhex(resp["envelope"])

        # Verify server certificate
        server_cert = x509.load_pem_x509_certificate(cert_bytes)
        server_pub = server_cert.public_key()
        # Verify CA signed the server cert
        ca_cert.public_key().verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()))
        print("[Client] Server certificate verified.")

        # Verify server signature
        verify(server_pub, cert_bytes + beta + eph_pub_bytes, sig)
        print("[Client] Server signature verified.")
        transcript += cert_bytes + beta + eph_pub_bytes

        # Recover rw from OPRF and decrypt envelope
        rw = oprf_client_finalize(beta, r_key, password_bytes)
        from crypto.aes_gcm import decrypt as ae_dec
        client_lt_key_bytes = ae_dec(rw[:32], envelope)
        print("[Client] Envelope decrypted, client key recovered.")

        # Client ephemeral DH key
        client_eph = ec.generate_private_key(ec.SECP256R1())
        client_eph_pub = client_eph.public_key().public_bytes(
            ser.Encoding.X962, ser.PublicFormat.CompressedPoint)
        transcript += client_eph_pub

        send_msg(conn, json.dumps({"eph_pub": client_eph_pub.hex()}).encode())

        # Derive keys
        server_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), eph_pub_bytes)
        shared = client_eph.exchange(ec.ECDH(), server_eph_pub)
        transcript_hash = hashlib.sha256(transcript).digest()
        keys = derive_keys(shared, transcript_hash)

        # Key confirmation
        server_confirm = json.loads(recv_msg(conn))
        mac1_expected = hmac.new(
            keys["server_hs_key"],
            b"server finished" + transcript_hash,
            hashlib.sha256).digest()
        assert server_confirm["mac"] == mac1_expected.hex(), "Server key confirmation FAILED"
        print("[Client] Server key confirmed.")

        mac2 = hmac.new(
            keys["client_hs_key"],
            b"client finished" + transcript_hash,
            hashlib.sha256).digest()
        send_msg(conn, json.dumps({"mac": mac2.hex()}).encode())
        print("[Client] Handshake complete. Secure channel established.")

        # Secure messaging
        client_key_enc = keys["client_app_key"]
        server_key_enc = keys["server_app_key"]
        while True:
            msg = input("You: ")
            if msg.lower() == "quit":
                break
            send_msg(conn, encrypt(client_key_enc, msg.encode()))
            response = recv_msg(conn)
            print(f"Server: {decrypt(server_key_enc, response).decode()}")

if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "chat"
    username = input("Username: ")
    password = input("Password: ")
    if mode == "register":
        register(username, password)
    else:
        handshake_and_chat(username, password)