from dataclasses import dataclass
from typing import Optional, Tuple, Dict

from crypto import utils
from crypto.utils import CryptoError
from crypto.keys import IdentityKeyStore

from cryptography.hazmat.primitives.asymmetric import ed25519


# ==============================
# PreKey Bundle
# ==============================

@dataclass
class PreKeyBundle:
    identity_pubkey: str
    signing_pubkey: str
    signed_prekey: str
    signed_prekey_signature: bytes
    one_time_prekey: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "identity_pubkey": self.identity_pubkey,
            "signing_pubkey": self.signing_pubkey,
            "signed_prekey": self.signed_prekey,
            "signed_prekey_signature": self.signed_prekey_signature.hex(),
            "one_time_prekey": self.one_time_prekey
        }

    @staticmethod
    def from_dict(d: dict) -> "PreKeyBundle":
        return PreKeyBundle(
            identity_pubkey=d["identity_pubkey"],
            signing_pubkey=d["signing_pubkey"],
            signed_prekey=d["signed_prekey"],
            signed_prekey_signature=bytes.fromhex(d["signed_prekey_signature"]),
            one_time_prekey=d.get("one_time_prekey")
        )

    def verify_signature(self) -> bool:
        try:
            sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(self.signing_pubkey)
            )

            spk_bytes = bytes.fromhex(self.signed_prekey)

            sign_pub.verify(self.signed_prekey_signature, spk_bytes)
            return True

        except Exception:
            return False


# ==============================
# Initiator (Alice)
# ==============================

class X3DHInitiator:

    def __init__(self, identity_keystore: IdentityKeyStore):
        self.identity_keystore = identity_keystore

    def initiate(self, their_bundle: PreKeyBundle) -> Tuple[bytes, Dict,object]:
        try:
            # Verify signed prekey
            if not their_bundle.verify_signature():
                raise CryptoError("Invalid signed prekey signature")

            alice_pub = self.identity_keystore.get_public_key()

            bob_identity = utils.decode_pubkey(their_bundle.identity_pubkey)
            bob_spk = utils.decode_pubkey(their_bundle.signed_prekey)

            # Ephemeral key
            eph_priv, eph_pub = utils.generate_keypair()

            with self.identity_keystore.use_private_key() as alice_priv:
                # DH operations
                dh1 = utils.dh(alice_priv, bob_spk)
                dh2 = utils.dh(eph_priv, bob_identity)
                dh3 = utils.dh(eph_priv, bob_spk)

                dh4 = b""
                if their_bundle.one_time_prekey:
                    bob_opk = utils.decode_pubkey(their_bundle.one_time_prekey)
                    dh4 = utils.dh(eph_priv, bob_opk)

            # Domain-separated combine
            combined = (
                b"\x01" + dh1 +
                b"\x02" + dh2 +
                b"\x03" + dh3 +
                b"\x04" + dh4
            )

            shared_secret = utils.hkdf(
                input_key_material=combined,
                length=32,
                salt=b"x3dh-salt",
                info=b"x3dh-key-agreement"
            )

            ratchet_priv, ratchet_pub = utils.generate_keypair()

            initial_message = {
                "identity_pubkey": utils.encode_pubkey(alice_pub),
                "ephemeral_pubkey": utils.encode_pubkey(eph_pub),
                "one_time_prekey": their_bundle.one_time_prekey,
                "ratchet_pubkey": utils.encode_pubkey(ratchet_pub),  # ← new
            }

            # Cleanup
            eph_priv = None

            return shared_secret, initial_message, ratchet_priv

        except CryptoError:
            raise
        except Exception as e:
            raise CryptoError("X3DH initiation failed") from e


# ==============================
# Responder (Bob)
# ==============================

class X3DHResponder:

    def __init__(self, identity_keystore: IdentityKeyStore, prekey_store):
        self.identity_keystore = identity_keystore
        self.prekey_store = prekey_store

    def accept(self, initial_message: dict) -> bytes:
        try:
            alice_identity = utils.decode_pubkey(initial_message["identity_pubkey"])
            alice_eph = utils.decode_pubkey(initial_message["ephemeral_pubkey"])

            with self.identity_keystore.use_private_key() as bob_priv:
                bob_spk_priv = self.prekey_store.get_signed_prekey_private()

                # DH operations (correct symmetric pairing)
                dh1 = utils.dh(bob_spk_priv, alice_identity)
                dh2 = utils.dh(bob_priv, alice_eph)
                dh3 = utils.dh(bob_spk_priv, alice_eph)

                dh4 = b""
                opk_hex = initial_message.get("one_time_prekey")

                if opk_hex:
                    opk_priv = self.prekey_store.get_private_prekey(opk_hex)
                    dh4 = utils.dh(opk_priv, alice_eph)
                    self.prekey_store.consume_prekey(opk_hex)

            combined = (
                b"\x01" + dh1 +
                b"\x02" + dh2 +
                b"\x03" + dh3 +
                b"\x04" + dh4
            )

            shared_secret = utils.hkdf(
                input_key_material=combined,
                length=32,
                salt=b"x3dh-salt",
                info=b"x3dh-key-agreement"
            )

            return shared_secret

        except CryptoError:
            raise
        except Exception as e:
            raise CryptoError("X3DH acceptance failed") from e


# ==============================
# PreKey Store
# ==============================

class PreKeyStore:
    """
    In-memory prekey store.
    Replace with persistent DB later.
    """

    def __init__(self):
        self._one_time = {}
        self._signed_prekey = None  # (priv, pub, signature)

    # ---------- Signed PreKey ----------

    def generate_signed_prekey(self, signing_private):
        priv, pub = utils.generate_keypair()

        pub_bytes = pub.public_bytes_raw()
        signature = signing_private.sign(pub_bytes)

        self._signed_prekey = (priv, pub, signature)

        return {
            "pubkey": utils.encode_pubkey(pub),
            "signature": signature.hex()
        }

    def get_signed_prekey_private(self):
        if not self._signed_prekey:
            raise CryptoError("Signed prekey not initialized")
        return self._signed_prekey[0]

    def get_signed_prekey_public(self):
        if not self._signed_prekey:
            raise CryptoError("Signed prekey not initialized")
        return utils.encode_pubkey(self._signed_prekey[1])

    def get_signed_prekey_signature(self):
        if not self._signed_prekey:
            raise CryptoError("Signed prekey not initialized")
        return self._signed_prekey[2]

    # ---------- One-Time PreKeys ----------

    def generate_prekeys(self, count: int):
        result = []

        for _ in range(count):
            priv, pub = utils.generate_keypair()
            pub_hex = utils.encode_pubkey(pub)

            self._one_time[pub_hex] = priv

            result.append({"pubkey": pub_hex})

        return result

    def get_private_prekey(self, pubkey_hex: str):
        if pubkey_hex not in self._one_time:
            raise CryptoError("Prekey not found")
        return self._one_time[pubkey_hex]

    def consume_prekey(self, pubkey_hex: str):
        if pubkey_hex in self._one_time:
            del self._one_time[pubkey_hex]


# ==============================
# Bundle Creation Helper
# ==============================

def create_prekey_bundle(
    keystore: IdentityKeyStore,
    prekey_store: PreKeyStore
) -> PreKeyBundle:

    identity_pub = keystore.get_public_key()
    signing_pub = keystore.get_signing_public_key()

    with keystore.use_signing_key() as signing_priv:
        spk = prekey_store.generate_signed_prekey(signing_priv)

    opk = prekey_store.generate_prekeys(1)[0]["pubkey"]

    return PreKeyBundle(
        identity_pubkey=utils.encode_pubkey(identity_pub),
        signing_pubkey=signing_pub.public_bytes_raw().hex(),
        signed_prekey=spk["pubkey"],
        signed_prekey_signature=bytes.fromhex(spk["signature"]),
        one_time_prekey=opk
    )