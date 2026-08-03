#!/usr/bin/env python3
"""
SecureChat Client — Alice's side
Sends encrypted messages to Bob
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

# ── Load Alice's keys ──
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

# ── Decrypt & Verify ──
def decrypt_message(receiver_private_key, sender_public_key,
                    encrypted_package, expected_sender):
    package = json.loads(encrypted_package)

    print(f"\n{'='*50}")
    print(f"📨 REPLY RECEIVED from {package['sender']}")

    if package['sender'] != expected_sender:
        print(f"❌ SENDER MISMATCH!")
        return None

    encrypted_session_key = base64.b64decode(package['encrypted_key'])
    session_key = receiver_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Fernet(session_key)
    encrypted_message = base64.b64decode(package['encrypted_message'])
    decrypted_message = cipher.decrypt(encrypted_message).decode()

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
        print(f"✅ Verified!")
    except Exception:
        print(f"❌ Verification FAILED!")
        return None

    return decrypted_message

# ── Main Client ──
def start_client():
    alice_private = load_private_key('secure_chat_keys/alice_private.pem')
    bob_public    = load_public_key('secure_chat_keys/bob_public.pem')
    alice_public  = load_public_key('secure_chat_keys/alice_public.pem')
    bob_private   = load_private_key('secure_chat_keys/bob_private.pem')

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 9999))

    print("🔐 SecureChat Client — Alice")
    print("="*50)
    print("✅ Connected to Bob!")
    print("Type your message and press Enter")
    print("Type 'quit' to exit\n")

    try:
        while True:
            # Alice types message
            message = input("Alice (you): ")
            if message.lower() == 'quit':
                break

            # Encrypt and send
            encrypted = encrypt_message(
                alice_private, bob_public,
                message, "Alice"
            )
            client.send(encrypted.encode())
            print(f"✅ Encrypted message sent!")

            # Receive Bob's reply
            data = client.recv(65536).decode()
            if not data:
                break

            reply = decrypt_message(
                alice_private, bob_public,
                data, "Bob"
            )
            if reply:
                print(f"\n💬 Bob: {reply}\n")

    except KeyboardInterrupt:
        print("\n🔴 Client stopped")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()
