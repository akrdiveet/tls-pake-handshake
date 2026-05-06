# tls-pake-handshake
TLS 1.3 with Password-Authenticated Key Exchange (PAKE)

An educational implementation of a TLS 1.3-style handshake that authenticates the **server** via a CA-issued certificate and authenticates the **client** via a password-authenticated key exchange (PAKE) inspired by OPAQUE.

This is a class project for CSE 539 Applied Cryptography at ASU. It uses compact JSON socket messages and a simplified OPAQUE-style construction so each cryptographic component is easy to inspect.

***

## What's Implemented

- CA public key distribution and server certificate validation
- Server digital signatures over handshake messages (ECDSA P-256)
- Password-based client authentication via a blinded OPRF flow
- Ephemeral ECDH key exchange for forward secrecy
- HKDF-based handshake and application traffic key derivation
- AES-256-GCM authenticated encryption after the handshake
- Client and server running as separate local socket processes on `127.0.0.1:8443`

***

## Setup

Requires **Python 3.9+**.

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install cryptography

# Generate CA keys and server certificate (run once)
python ca/ca_keygen.py
```

***

## Run the Protocol

**Start the server** in one terminal:

```bash
source venv/bin/activate
python server/server.py
```

**Register a user** in another terminal:

```bash
source venv/bin/activate
python client/client.py register
# Enter username and password when prompted
```

**Run the handshake + secure chat** in a third terminal:

```bash
source venv/bin/activate
python client/client.py
# Enter the same username and password used during registration
```

Expected output:
```
[Client] Server certificate verified.
[Client] Server signature verified.
[Client] Envelope decrypted, client key recovered.
[Client] Server key confirmed.
[Client] Handshake complete. Secure channel established.
You: hello
Server: ACK: hello
```

***

## Files

| File | Description |
|------|-------------|
| `ca/ca_keygen.py` | Generates CA key pair, self-signed cert, and signed server certificate |
| `crypto/oprf.py` | OPRF registration and online password proof over P-256 |
| `crypto/kdf.py` | HKDF extract + expand for handshake and application traffic secrets |
| `crypto/aes_gcm.py` | AES-256-GCM record protection |
| `crypto/signature.py` | ECDSA sign/verify and certificate loading |
| `server/server.py` | Server socket process — registration and handshake handler |
| `client/client.py` | Client socket process — registration and handshake flow |
| `db/users.json` | Server-side user store (OPRF key + encrypted client envelope) |
| `report.pdf` | Project report: architecture, security intuition, implementation |

***

> This is a class project implementation, not production TLS. Cipher suite negotiation is omitted per assignment scope.