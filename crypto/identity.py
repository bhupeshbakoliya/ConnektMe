# ConnektMe/crypto/identity.py

from typing import Dict

from crypto.keys import IdentityKeyStore
from crypto import utils
from crypto.utils import CryptoError


# ==============================
# Exceptions
# ==============================

class IdentityError(Exception):
    pass


# ==============================
# Identity
# ==============================

class Identity:
    """
    Identity abstraction built on top of IdentityKeyStore.

    - No key generation here
    - Everything derived from existing public key
    - Responsible for:
        • user ID
        • fingerprint
        • QR payload construction/validation
    """

    def __init__(self, keystore: IdentityKeyStore):
        if not isinstance(keystore, IdentityKeyStore):
            raise IdentityError("Invalid keystore provided")

        self.keystore = keystore

        try:
            self._pubkey = keystore.get_public_key()
            self._user_id = utils.encode_pubkey(self._pubkey)
        except Exception as e:
            raise IdentityError("Failed to initialize identity") from e

    # ==============================
    # Core Identity
    # ==============================

    def get_user_id(self) -> str:
        """
        Canonical identity string (hex public key)
        """
        return self._user_id

    def get_short_id(self) -> str:
        """
        First 16 chars of user ID (UI display)
        """
        return self._user_id[:16]

    def get_fingerprint(self) -> str:
        """
        Grouped fingerprint for manual verification
        """
        uid = self._user_id
        return " ".join(uid[i:i+8] for i in range(0, len(uid), 8))

    # ==============================
    # Verification
    # ==============================

    def verify_fingerprint(self, peer_id: str, claimed_fingerprint: str) -> bool:
        """
        Constant-time verification of fingerprint
        """
        try:
            normalized = claimed_fingerprint.replace(" ", "").lower()
            peer_normalized = peer_id.lower()

            peer_bytes = bytes.fromhex(peer_normalized)
            claimed_bytes = bytes.fromhex(normalized)

            return utils.constant_time_compare(peer_bytes, claimed_bytes)

        except Exception:
            return False  # fail closed

    # ==============================
    # QR Payload
    # ==============================

    def build_qr_payload(self, ip: str, port: int) -> Dict:
        """
        Construct payload for QR or shareable string

        NOTE: identity layer does NOT discover IP/port
        """
        try:
            if not isinstance(ip, str) or not ip.strip():
                raise IdentityError("Invalid IP")

            if not isinstance(port, int) or not (1 <= port <= 65535):
                raise IdentityError("Invalid port")

            return {
                "id": self._user_id,
                "pubkey": self._user_id,
                "ip": ip,
                "port": port
            }

        except Exception as e:
            raise IdentityError("Failed to build QR payload") from e

    @staticmethod
    def parse_qr_payload(payload: Dict) -> Dict:
        """
        Validate and normalize incoming QR payload
        """
        try:
            required = {"id", "pubkey", "ip", "port"}

            if not isinstance(payload, dict):
                raise IdentityError("Payload must be a dict")

            if not required.issubset(payload.keys()):
                raise IdentityError("Missing required fields")

            user_id = payload["id"]
            pubkey_hex = payload["pubkey"]
            ip = payload["ip"]
            port = payload["port"]

            if not isinstance(user_id, str) or not isinstance(pubkey_hex, str):
                raise IdentityError("Invalid key format")

            if not isinstance(ip, str) or not isinstance(port, int):
                raise IdentityError("Invalid network fields")

            # Decode and canonicalize pubkey
            pubkey_obj = utils.decode_pubkey(pubkey_hex)
            canonical = utils.encode_pubkey(pubkey_obj)

            # Enforce ID == pubkey
            if canonical != user_id:
                raise IdentityError("ID/pubkey mismatch")

            return {
                "id": canonical,
                "pubkey": canonical,
                "ip": ip,
                "port": port
            }

        except CryptoError:
            raise IdentityError("Invalid public key encoding")
        except IdentityError:
            raise
        except Exception as e:
            raise IdentityError("Invalid QR payload") from e

    # ==============================
    # Export Bundle
    # ==============================

    def export_public_bundle(self) -> Dict:
        """
        Canonical public bundle for relay registration

        Delegates to keystore to avoid divergence
        """
        try:
            return self.keystore.export_bundle()
        except Exception as e:
            raise IdentityError("Failed to export public bundle") from e