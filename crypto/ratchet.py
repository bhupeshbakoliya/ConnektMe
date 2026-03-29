from dataclasses import dataclass
from typing import Dict, Tuple

from crypto import utils
from crypto.utils import CryptoError

from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import x25519


# ==============================
# Exceptions
# ==============================

class DecryptionError(Exception):
    pass


# ==============================
# Helpers
# ==============================

def _ensure_bytes(x):
    if isinstance(x, bytes):
        return x

    if isinstance(x, str):
        # dh_pub MUST be hex from encode_pubkey
        return bytes.fromhex(x)  # let ValueError propagate

    raise CryptoError("Invalid type for associated data field")

def _normalize_pubkey(pubkey):
    if hasattr(pubkey, "public_bytes"):
        return pubkey
    if isinstance(pubkey, bytes):
        return x25519.X25519PublicKey.from_public_bytes(pubkey)
    if isinstance(pubkey, str):
        return utils.decode_pubkey(pubkey)
    raise CryptoError("Invalid public key format")


def _kdf_rk(root_key: bytes, dh_out: bytes):
    # HKDF-Extract
    h = hmac.HMAC(root_key, hashes.SHA256())
    h.update(dh_out)
    prk = h.finalize()

    # HKDF-Expand
    new_rk = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"root"
    ).derive(prk)

    ck = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"chain"
    ).derive(prk)

    return new_rk, ck


def _kdf_ck(chain_key: bytes):
    """
    Signal-style chain KDF:
    Extract once (salt=b"ck", IKM=chain_key) → Expand twice
    """

    # HKDF-Extract: PRK = HMAC(salt="ck", IKM=chain_key)
    h = hmac.HMAC(b"ck", hashes.SHA256())
    h.update(chain_key)
    prk = h.finalize()

    # HKDF-Expand
    mk = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"msg"
    ).derive(prk)

    next_ck = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"next"
    ).derive(prk)

    return mk, next_ck


# ==============================
# Ratchet State
# ==============================

@dataclass
class RatchetState:
    root_key: bytes
    sending_chain_key: bytes
    receiving_chain_key: bytes

    sending_dh_keypair: Tuple
    their_dh_pubkey: object

    send_count: int
    recv_count: int
    prev_send_count: int

    skipped_message_keys: Dict[Tuple[str, int], bytes]

    def to_dict(self) -> dict:
        return {
            "root_key": self.root_key.hex(),
            "sending_chain_key": self.sending_chain_key.hex() if self.sending_chain_key else None,
            "receiving_chain_key": self.receiving_chain_key.hex() if self.receiving_chain_key else None,
            "sending_dh_priv": utils.encode_privkey(self.sending_dh_keypair[0]).hex(),
            "sending_dh_pub": utils.encode_pubkey(self.sending_dh_keypair[1]),
            "their_dh_pubkey": utils.encode_pubkey(self.their_dh_pubkey),
            "send_count": self.send_count,
            "recv_count": self.recv_count,
            "prev_send_count": self.prev_send_count,
            "skipped": {
                f"{k[0]}:{k[1]}": v.hex()
                for k, v in self.skipped_message_keys.items()
            }
        }

    @staticmethod
    def from_dict(d: dict) -> "RatchetState":
        priv = utils.decode_privkey(bytes.fromhex(d["sending_dh_priv"]))
        pub = utils.decode_pubkey(d["sending_dh_pub"])

        skipped = {}
        for k, v in d["skipped"].items():
            pubkey, idx = k.split(":")
            skipped[(pubkey, int(idx))] = bytes.fromhex(v)

        return RatchetState(
            root_key=bytes.fromhex(d["root_key"]),
            sending_chain_key=bytes.fromhex(d["sending_chain_key"]) if d["sending_chain_key"] else None,
            receiving_chain_key=bytes.fromhex(d["receiving_chain_key"]) if d["receiving_chain_key"] else None,
            sending_dh_keypair=(priv, pub),
            their_dh_pubkey=_normalize_pubkey(d["their_dh_pubkey"]),
            send_count=d["send_count"],
            recv_count=d["recv_count"],
            prev_send_count=d["prev_send_count"],
            skipped_message_keys=skipped
        )

    def __repr__(self):
        return "<RatchetState [redacted]>"


# ==============================
# Double Ratchet
# ==============================

class DoubleRatchet:

    MAX_SKIP = 1000
    MAX_SKIPPED_TOTAL = 5000

    def __init__(self, state: RatchetState):
        self.state = state

    @classmethod
    def from_shared_secret(cls, shared_secret: bytes, their_pubkey, is_initiator: bool,
                           initiator_ratchet_priv=None):
        their_pub_obj = _normalize_pubkey(their_pubkey)

        if is_initiator:
            if initiator_ratchet_priv is None:
                raise CryptoError("Initiator must supply ratchet keypair")
            priv = initiator_ratchet_priv
            pub = priv.public_key()
            sending_chain_key = utils.hkdf(shared_secret, 32, b"rk", b"init-chain")
            receiving_chain_key =  utils.hkdf(shared_secret, 32, b"rk", b"init-chain-resp")
        else:
            priv, pub = utils.generate_keypair()
            receiving_chain_key = utils.hkdf(shared_secret, 32, b"rk", b"init-chain")
            sending_chain_key = utils.hkdf(shared_secret, 32, b"rk", b"init-chain-resp")

        state = RatchetState(
            root_key=shared_secret,
            sending_chain_key=sending_chain_key,
            receiving_chain_key=receiving_chain_key,
            sending_dh_keypair=(priv, pub),
            their_dh_pubkey=their_pub_obj,
            send_count=0,
            recv_count=0,
            prev_send_count=0,
            skipped_message_keys={}
        )

        return cls(state)

    def encrypt(self, plaintext: bytes) -> dict:
        if self.state.sending_chain_key is None:
            raise CryptoError("Sending chain not initialized")

        mk, self.state.sending_chain_key = _kdf_ck(self.state.sending_chain_key)

        n = self.state.send_count
        pn = self.state.prev_send_count
        self.state.send_count += 1

        dh_pub = utils.encode_pubkey(self.state.sending_dh_keypair[1])
        ad = _ensure_bytes(dh_pub) + n.to_bytes(4, "big") + pn.to_bytes(4, "big")

        ct, nonce, tag = utils.aes_gcm_encrypt(mk, plaintext, ad)

        del mk

        return {
            "dh_pub": dh_pub,
            "n": n,
            "pn": pn,
            "ciphertext": ct,
            "nonce": nonce,
            "tag": tag
        }

    def decrypt(self, envelope: dict) -> bytes:
        try:
            dh_pub = envelope["dh_pub"]
            n = envelope["n"]
            pn = envelope["pn"]

            ad = _ensure_bytes(dh_pub) + n.to_bytes(4, "big") + pn.to_bytes(4, "big")
            key_id = (dh_pub, n)

            # skipped keys
            if key_id in self.state.skipped_message_keys:
                mk = self.state.skipped_message_keys[key_id]

                pt = utils.aes_gcm_decrypt(
                    mk,
                    envelope["ciphertext"],
                    envelope["nonce"],
                    envelope["tag"],
                    ad
                )

                del self.state.skipped_message_keys[key_id]
                del mk
                return pt

            # ---- DH ratchet ----
            if dh_pub != utils.encode_pubkey(self.state.their_dh_pubkey):

                # NOTE:
                # Drain old epoch before ratchet.
                # Old chain is consumed and replaced after ratchet.
                old_recv = self.state.recv_count
                self.state.recv_count = 0
                self._cache_skipped_keys(pn)
                self.state.recv_count = old_recv

                self._dh_ratchet_step(_normalize_pubkey(dh_pub))

                # explicit invariant
                self.state.recv_count = 0

            # skip forward
            self._cache_skipped_keys(n)

            # decrypt
            mk, self.state.receiving_chain_key = _kdf_ck(self.state.receiving_chain_key)
            self.state.recv_count += 1

            pt = utils.aes_gcm_decrypt(
                mk,
                envelope["ciphertext"],
                envelope["nonce"],
                envelope["tag"],
                ad
            )

            del mk
            return pt

        except Exception as e:
            raise DecryptionError("Decryption failed") from e

    def _dh_ratchet_step(self, their_new_pubkey):
        self.state.prev_send_count = self.state.send_count
        self.state.send_count = 0
        self.state.their_dh_pubkey = their_new_pubkey

        dh_out = utils.dh(self.state.sending_dh_keypair[0], their_new_pubkey)
        self.state.root_key, self.state.receiving_chain_key = _kdf_rk(self.state.root_key, dh_out)

        priv, pub = utils.generate_keypair()
        self.state.sending_dh_keypair = (priv, pub)

        dh_out2 = utils.dh(priv, their_new_pubkey)
        self.state.root_key, self.state.sending_chain_key = _kdf_rk(self.state.root_key, dh_out2)

    def _cache_skipped_keys(self, until_index: int):
        if self.state.receiving_chain_key is None:
            return

        if self.state.recv_count + self.MAX_SKIP < until_index:
            raise DecryptionError("Too many skipped messages")

        while self.state.recv_count < until_index:
            mk, self.state.receiving_chain_key = _kdf_ck(self.state.receiving_chain_key)

            key = (
                utils.encode_pubkey(self.state.their_dh_pubkey),
                self.state.recv_count
            )

            self._store_skipped_key(key, mk)
            self.state.recv_count += 1

    def _store_skipped_key(self, key, mk):
        if len(self.state.skipped_message_keys) >= self.MAX_SKIPPED_TOTAL:
            oldest = next(iter(self.state.skipped_message_keys))
            del self.state.skipped_message_keys[oldest]

        self.state.skipped_message_keys[key] = mk

    def get_state(self) -> RatchetState:
        return self.state