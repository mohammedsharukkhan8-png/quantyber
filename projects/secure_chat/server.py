#!/usr/bin/env python3
"""
SecureChat Server — Bob's side
Listens for encrypted messages from Alice
"""

import socket
import json
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# ── Load Bob's keys ──
def load_private_key(filepath):
    with open(filepath, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(), password=None,
            backend=default_backend()
        )

def load_public_key(filepath):
    with open(filepath, 'rb') as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )

# ── Decrypt & Verify Message ──
def decrypt_message(receiver_private_key, sender_public_key,
                    encrypted_package, expected_sender):
    package = json.loads(encrypted_package)

    print(f"\n{'='*50}")
    print(f"📨 MESSAGE RECEIVED")
    print(f"From:      {package['sender']}")
    print(f"Time:      {package['timestamp']}")

    # Verify sender
    if package['sender'] != expected_sender:
        print(f"❌ SENDER MISMATCH — Attack detected!")
        return None

    # Decrypt session key
    encrypted_session_key = base64.b64decode(package['encrypted_key'])
    session_key = receiver_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt message
    cipher = Fernet(session_key)
    encrypted_message = base64.b64decode(package['encrypted_message'])
    decrypted_message = cipher.decrypt(encrypted_message).decode()

    # Verify signature
    signed_content = f"{package['sender']}:{package['timestamp']}:{decrypted_message}"
    signed_hash = hashlib.sha256(signed_content.encode()).digest()

    try:
        signature = base64.b64decode(package['signature'])
        sender_public_key.verify(
            signature, signed_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"✅ Signature verified!")
    except Exception:
        print(f"❌ Signature FAILED — Tampered message!")
        return None

    # Verify hash
    if hashlib.sha256(signed_content.encode()).hexdigest() == package['message_hash']:
        print(f"✅ Integrity verified!")
    else:
        print(f"❌ Hash mismatch!")
        return None

    return decrypted_message

# ── Encrypt Message ──
def encrypt_message(sender_private_key, receiver_public_key,
                    message, sender_name):
    session_key = Fernet.generate_key()
    cipher = Fernet(session_key)
    encrypted_message = cipher.encrypt(message.encode())

    encrypted_session_key = receiver_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    timestamp = datetime.now().isoformat()
    signed_content = f"{sender_name}:{timestamp}:{message}"
    signed_hash = hashlib.sha256(signed_content.encode()).digest()

    signature = sender_private_key.sign(
        signed_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    package = {
        "sender":            sender_name,
        "timestamp":         timestamp,
        "encrypted_message": base64.b64encode(encrypted_message).decode(),
        "encrypted_key":     base64.b64encode(encrypted_session_key).decode(),
        "signature":         base64.b64encode(signature).decode(),
        "message_hash":      hashlib.sha256(signed_content.encode()).hexdigest()
    }
    return json.dumps(package)

# ── Main Server ──
def start_server():
    # Load keys
    bob_private  = load_private_key('secure_chat_keys/bob_private.pem')
    alice_public = load_public_key('secure_chat_keys/alice_public.pem')
    bob_public   = load_public_key('secure_chat_keys/bob_public.pem')

    # Start TCP server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 9999))
    server.listen(1)

    print("🔐 SecureChat Server — Bob")
    print("="*50)
    print("Waiting for Alice to connect...")

    conn, addr = server.accept()
    print(f"✅ Alice connected from {addr}")

    try:
        while True:
            # Receive message
            data = conn.recv(65536).decode()
            if not data:
                break

            # Decrypt and display
            message = decrypt_message(
                bob_private, alice_public,
                data, "Alice"
            )

            if message:
                print(f"\n💬 Alice: {message}")

                # Bob replies
                reply = input("\nBob (you): ")
                if reply.lower() == 'quit':
                    break

                # Encrypt and send reply
                encrypted_reply = encrypt_message(
                    bob_private, alice_public,
                    reply, "Bob"
                )
                conn.send(encrypted_reply.encode())
                print(f"✅ Encrypted reply sent!")

    except KeyboardInterrupt:
        print("\n🔴 Server stopped")
    finally:
        conn.close()
        server.close()

if __name__ == "__main__":
    start_server()
