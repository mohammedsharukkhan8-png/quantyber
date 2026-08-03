# 🔐 SecureChat — End-to-End Encrypted Chat

A command-line encrypted messaging application built
from scratch using hybrid cryptography, digital
signatures and TCP sockets.

Built as Phase 1 Capstone of the Quantyber
Quantum + Cybersecurity learning journey.

---

## 🛡️ Security Architecturee

Alice Bob
| |
|── RSA-2048 Key Exchange ───>|
| |
|── AES Encrypted Message ───>| (Fernet/AES-128)
|── RSA Encrypted Session Key>| (OAEP padding)
|── SHA-256 Digital Signature>| (PSS padding)
|── Message Hash (integrity) >| (SHA-256)
| |
|<── Encrypted Reply ─────────|

## 🔒 Security Properties

| Property | Implementation | Guarantee |
|----------|---------------|-----------|
| Confidentiality | AES-128 (Fernet) | Only receiver can read |
| Key Security | RSA-2048 (OAEP) | Only receiver decrypts key |
| Authentication | RSA Digital Signature | Proves sender identity |
| Integrity | SHA-256 Hash | Detects tampering |
| Non-repudiation | PSS Signature | Sender cannot deny |
| Replay Protection | Timestamp in signature | Blocks replay attacks |

---

## ⚙️ Tech Stack

- **Language:** Python 3.14
- **Cryptography:** `cryptography` library
- **Networking:** TCP Sockets (`socket`)
- **Encryption:** RSA-2048 + AES-128 (Hybrid)
- **Signatures:** RSA-PSS with SHA-256
- **Transport:** JSON over TCP

---

## 🚀 How to Run

### Prerequisites
```bash
pip install cryptography
```

### Step 1 — Generate Keys
```bash
python generate_keys.py
```

### Step 2 — Start Bob (Server) — Terminal 1
```bash
python server.py
```

### Step 3 — Start Alice (Client) — Terminal 2
```bash
python client.py
```

### Step 4 — Chat!
Alice (you): Hello Bob! This is encrypted 🔐
✅ Encrypted message sent!

📨 REPLY RECEIVED from Bob
✅ Verified!

💬 Bob: Loud and clear Alice! 🔐

---

## 🔍 Vulnerability Testing

The system was tested against:

| Attack | Result |
|--------|--------|
| Message tampering | ❌ Detected — Fernet InvalidToken |
| Sender spoofing | ❌ Blocked — Signature mismatch |
| Replay attack | ❌ Blocked — Timestamp in signature |
| Man-in-the-middle | ❌ Blocked — RSA key verification |

---

## 📁 Project Structure

secure_chat/
├── server.py # Bob's server
├── client.py # Alice's client
├── secure_chat_keys/
│ ├── alice_private.pem # Alice's private key
│ ├── alice_public.pem # Alice's public key
│ ├── bob_private.pem # Bob's private key
│ └── bob_public.pem # Bob's public key
├── secure_chat_audit.log # Audit trail
└── README.md

---

## 🧠 Concepts Applied

- **Week 2:** RSA encryption & key generation
- **Week 3:** SHA-256 hashing, digital signatures, PKI
- **Week 4:** TCP socket networking
- **Week 5:** Input validation & attack prevention
- **Week 6:** Audit logging & incident trail

---

## 👨‍💻 Author

**Mohammed Sharuk Khan**
2nd Year B.Sc CS | Rajalakshmi Institute of Technology, Chennai
GitHub: [mohammedsharukkhan8-png](https://github.com/mohammedsharukkhan8-png)

Part of the **Quantyber** — Quantum + Cybersecurity
self-directed learning journey.

Target Role: Security Engineer (PQC-focused)
