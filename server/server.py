import socket, json, os, hashlib, hmac, pickle
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crypto.signature import sign, verify, load_private_key, load_cert
from crypto.aes_gcm import encrypt, decrypt
from crypto.kdf import derive_keys

DB_PATH = "db/users.json"
os.makedirs("db", exist_ok=True)
if not os.path.exists(DB_PATH):
    json.dump({}, open(DB_PATH, "w"))

def load_db():
    return json.load(open(DB_PATH))

def save_db(db):
    json.dump(db, open(DB_PATH, "w"))

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

def handle_client(conn):
    server_key = load_private_key("server/server_key.pem")
    server_cert = load_cert("server/server_cert.pem")
    ca_cert = load_cert("ca/ca_cert.pem")

    # Step 1: Receive client hello (username + intent)
    msg = json.loads(recv_msg(conn))
    username = msg["username"]
    intent = msg["intent"]  # "register" or "handshake"

    if intent == "register":
        # OPAQUE Registration: receive OPRF alpha + client envelope
        alpha_bytes = bytes.fromhex(msg["alpha"])

        # Generate OPRF key for this user
        oprf_key = ec.generate_private_key(ec.SECP256R1())
        oprf_key_bytes = oprf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()).hex()

        # Evaluate OPRF: beta = alpha^k
        from crypto.oprf import oprf_server_evaluate
        beta = oprf_server_evaluate(alpha_bytes, oprf_key)

        # Send beta to client
        send_msg(conn, json.dumps({"beta": beta.hex()}).encode())

        # Receive encrypted envelope from client
        env_msg = json.loads(recv_msg(conn))
        db = load_db()
        db[username] = {
            "oprf_key": oprf_key_bytes,
            "envelope": env_msg["envelope"]
        }
        save_db(db)
        send_msg(conn, b'{"status":"registered"}')
        print(f"[Server] User '{username}' registered.")
        return

    # HANDSHAKE PHASE
    # Step 2: Server sends certificate (signed)
    cert_pem = open("server/server_cert.pem", "rb").read()
    transcript = msg["client_hello"].encode()

    # Step 3: OPRF for client authentication
    alpha_bytes = bytes.fromhex(msg["alpha"])
    db = load_db()
    if username not in db:
        send_msg(conn, b'{"error":"unknown user"}')
        return

    oprf_key = serialization.load_pem_private_key(
        bytes.fromhex(db[username]["oprf_key"]), password=None)
    from crypto.oprf import oprf_server_evaluate
    beta = oprf_server_evaluate(alpha_bytes, oprf_key)

    # Step 4: Server ephemeral DH key
    eph_key = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint)

    # Sign: cert + beta + eph_pub
    server_msg = cert_pem + beta + eph_pub
    sig = sign(server_key, server_msg)
    transcript += server_msg

    send_msg(conn, json.dumps({
        "cert": cert_pem.hex(),
        "beta": beta.hex(),
        "eph_pub": eph_pub.hex(),
        "sig": sig.hex(),
        "envelope": db[username]["envelope"]
    }).encode())

    # Step 5: Receive client ephemeral pub key
    client_msg = json.loads(recv_msg(conn))
    client_eph_pub_bytes = bytes.fromhex(client_msg["eph_pub"])
    client_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_eph_pub_bytes)
    transcript += client_eph_pub_bytes

    # Step 6: Compute shared secret (ECDH)
    shared = eph_key.exchange(ec.ECDH(), client_eph_pub)
    transcript_hash = hashlib.sha256(transcript).digest()
    keys = derive_keys(shared, transcript_hash)
    server_key_enc = keys["server_app_key"]
    client_key_enc = keys["client_app_key"]

    # Step 7: Key confirmation
    mac1_expected = hmac.new(keys["server_hs_key"], b"server finished" + transcript_hash, hashlib.sha256).digest()
    mac2 = hmac.new(keys["client_hs_key"], b"client finished" + transcript_hash, hashlib.sha256).digest()
    send_msg(conn, json.dumps({"mac": mac1_expected.hex()}).encode())

    # Verify client MAC
    client_confirm = json.loads(recv_msg(conn))
    if client_confirm["mac"] != mac2.hex():
        send_msg(conn, b'{"error":"key confirmation failed"}')
        return

    print(f"[Server] Handshake complete with '{username}'.")

    # Step 8: Secure channel
    while True:
        data = recv_msg(conn)
        if not data:
            break
        plaintext = decrypt(client_key_enc, data)
        print(f"[Server] Received: {plaintext.decode()}")
        response = encrypt(server_key_enc, b"ACK: " + plaintext)
        send_msg(conn, response)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 8443))
        s.listen(5)
        print("[Server] Listening on 127.0.0.1:8443")
        while True:
            try:
                conn, addr = s.accept()
                print(f"[Server] Connection from {addr}")
                try:
                    handle_client(conn)
                except Exception as e:
                    print(f"[Server] Error handling client: {e}")
                finally:
                    conn.close()
            except KeyboardInterrupt:
                print("[Server] Shutting down.")
                break

if __name__ == "__main__":
    main()