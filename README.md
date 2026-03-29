# ConnektMe

> Peer-to-peer encrypted messaging — no accounts, no servers, no plaintext.

A Python CLI messenger built on Signal-protocol cryptography (X3DH + Double Ratchet). Your identity is your keypair. No sign-up, no email, no central authority. The relay server is optional and never sees your messages.

Built at **IIT Jammu** as a college project · 2026

---

## How it works

When you run ConnektMe for the first time, it generates an X25519 keypair and stores it encrypted on disk. Your public key **is** your user ID — there is no username, no account, no server that knows who you are.

To message someone, you exchange key bundles (a JSON file or QR code) out-of-band. ConnektMe then performs an X3DH handshake to establish a shared secret, and every subsequent message is encrypted with a unique key derived by the Double Ratchet. Old keys are deleted after use — even if your device is compromised later, past messages cannot be decrypted.

The relay server, if used, only ever stores opaque ciphertext blobs. It cannot read anything.

---

## Features

- **Keyless identity** — your X25519 public key is your ID, generated locally on first run
- **X3DH session initiation** — async key agreement; Bob doesn't need to be online when Alice initiates
- **Double Ratchet encryption** — per-message keys, forward secrecy, break-in recovery
- **Direct P2P over WebSocket** — works on LAN with no server at all
- **Optional relay server** — consent-gated; recipient must approve before any blob is delivered
- **SQLite persistence** — contacts, message history, ratchet state all stored locally
- **Typing indicators** — encrypted, goes through the ratchet like every other message
- **Vanishing messages** — TTL-based auto-delete enforced by both sender and receiver independently
- **One-time messages** — displayed once, never written to disk, sender notified on open
- **Delivery receipts** — server-signed acknowledgement on blob delivery

---

## Cryptographic pipeline

```
Identity keypair (X25519)  →  stored encrypted at rest (AES-256-GCM + HKDF)
         │
         ▼
X3DH handshake  →  4 DH operations  →  HKDF  →  shared secret
         │
         ▼
Double Ratchet
  ├── Symmetric ratchet  →  new message key per message (HKDF)
  └── DH ratchet         →  fresh DH on every reply (break-in recovery)
         │
         ▼
AES-256-GCM  →  ciphertext + nonce + tag  →  msgpack envelope  →  WebSocket
```

Wire envelope format:
```json
{
  "v": 1,
  "sender": "<hex pubkey>",
  "msg_id": "<uuid4>",
  "dh_pub": "<hex>",
  "n": 5,
  "pn": 3,
  "ct": "<AES-GCM ciphertext>",
  "ts": 1711500000
}
```

---

## Project structure

```
ConnektMe/
├── app.py                  # Entry point, asyncio CLI loop
│
├── crypto/
│   ├── keys.py             # Keypair generation, encrypted persistence
│   ├── identity.py         # User ID derivation, fingerprint, QR payload
│   ├── x3dh.py             # X3DH initiation and acceptance, PreKeyStore
│   ├── ratchet.py          # Double Ratchet encrypt / decrypt
│   └── utils.py            # HKDF, AES-GCM, X25519 helpers
│
├── net/
│   ├── server.py           # Local WebSocket listener (receive side)
│   ├── client.py           # Outbound WebSocket connector (send side)
│   ├── relay_client.py     # Relay server communication
│   └── protocol.py         # Message envelope, serialization, validation
│
├── db/
│   ├── store.py            # SQLite wrapper, schema initialization
│   ├── sessions.py         # Ratchet state persistence per peer
│   ├── messages.py         # Message history
│   └── contacts.py         # Contact list CRUD
│
├── cli/
│   ├── menu.py             # Interactive CLI menu
│   ├── chat.py             # Chat session UI
│   ├── contacts_menu.py    # Contact management UI
│   ├── commands.py         # Command handler (/id, /export-bundle, /quit)
│   └── display.py          # Output formatting
│
├── core/
│   ├── context.py          # AppContext — shared state across modules
│   ├── session.py          # InMemorySessionManager
│   └── bundle.py           # LocalBundleProvider
│
├── tests/
│   ├── test_ratchet.py
│   ├── test_x3dh.py
│   └── test_protocol.py
│
└── data/                   # Runtime data — gitignored
    ├── identity.key        # Encrypted keypair (created on first run)
    └── messages.db         # SQLite database
```

---

## Tech stack

| Layer | Library | Purpose |
|---|---|---|
| Encryption | `cryptography` (PyCA) | X25519, AES-GCM, HKDF |
| Networking | `asyncio` + `websockets` | Async P2P WebSocket transport |
| Relay server | `FastAPI` + `uvicorn` | REST + WebSocket API |
| Database | `sqlite3` (built-in) | Session state, messages, contacts |
| Voice (planned) | `aiortc` + `sounddevice` | WebRTC peer connection, Opus audio |
| Serialization | `msgpack` | Compact binary message envelope |
| NAT traversal | STUN | Discover public IP |

---

## Getting started

**Install dependencies**
```bash
python -m venv .venv
source .venv/bin/activate
pip install cryptography websockets msgpack qrcode pillow
```

**Run Alice (terminal 1)**
```bash
python app.py --data-dir data/alice --port 8765
```

**Run Bob (terminal 2)**
```bash
python app.py --data-dir data/bob --port 9000
```

**Exchange bundles**

In Alice's menu: `Contacts → Export my bundle` → saves `bundle_<id>.json`

In Bob's menu: `Contacts → Import peer bundle` → paste Alice's full ID and bundle path

Do the same in reverse so both sides have each other's bundle.

**Add contact and chat**

In each terminal: `Contacts → Add contact` → enter the other's full ID, IP (`127.0.0.1` for local), and port.

Then: `Start Chat → select contact → type messages`.

---

## Two operating modes

| Direct P2P | Relay-assisted |
|---|---|
| Both users online and reachable | Recipient offline or behind strict NAT |
| WebSocket direct device to device | Sender opts in, recipient must consent |
| Works on LAN with no server at all | Relay stores only encrypted ciphertext blobs |

NAT handling priority: same LAN (direct) → STUN hole punching (~70% success across networks) → relay fallback.

---

## Relay server (optional)

The relay never reads message content. It only handles:
- Public key bundle registration and fetch (for X3DH)
- Address directory (`local_ip`, `public_ip`, `port`) for P2P discovery
- Consent-gated blob store and forward for offline delivery
- Presence notifications (online/offline)

The relay is architecturally optional — on a LAN it is never needed.

---

## Planned features (roadmap)

- [ ] Relay server implementation (FastAPI)
- [ ] STUN-based public IP discovery
- [ ] UDP hole punching for cross-network P2P
- [ ] Encrypted voice calls via WebRTC (aiortc)
- [ ] QR code contact exchange
- [ ] Persistent ratchet state in SQLite

---

## Security properties

- **Forward secrecy** — old message keys are deleted after use. Past messages cannot be decrypted even with the current private key.
- **Break-in recovery** — after each DH ratchet step, an attacker who captured current state cannot decrypt future messages.
- **No metadata at relay** — the relay sees sender ID, recipient ID, and ciphertext size. Nothing else.
- **Consent gate** — the relay cannot deliver a message blob without an explicit accept from the recipient. This is enforced in the protocol, not just policy.
- **Keyless identity** — no password, no account. Losing your `identity.key` file means losing your identity. There is no recovery.

---

## License

Apache 2.0
