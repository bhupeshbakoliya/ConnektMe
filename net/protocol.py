# messenger/net/protocol.py

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any
import time
import uuid
import msgpack

from crypto import utils
from crypto.utils import CryptoError


# ==============================
# Exceptions
# ==============================

class ProtocolError(Exception):
    pass



# ==============================
# Message Types
# ==============================

class MessageType(str, Enum):
    CHAT = "chat"
    X3DH_INIT = "x3dh_init"
    X3DH_ACK = "x3dh_ack"
    TYPING = "typing"
    RECEIPT = "receipt"
    CONSENT_REQUEST = "consent_request"
    CONSENT_RESPONSE = "consent_response"
    HEARTBEAT = "heartbeat"
    ADDRESS_UPDATE = "address_update"


class ReceiptStatus(str, Enum):
    DELIVERED = "delivered"
    READ = "read"


# ==============================
# Envelope
# ==============================

@dataclass
class Envelope:
    version: int
    msg_type: MessageType
    msg_id: str
    sender_id: str
    recipient_id: str
    timestamp: int

    # Ratchet header
    dh_pub: str = ""
    n: int = 0
    pn: int = 0

    # Encrypted payload
    ciphertext: bytes = b""
    nonce: bytes = b""
    tag: bytes = b""

    # Message controls
    ttl: Optional[int] = None
    one_time: bool = False

    # Extra fields
    extra: Dict[str, Any] = field(default_factory=dict)

    # ==============================
    # Serialization (Binary)
    # ==============================

    def to_bytes(self) -> bytes:
        try:
            return msgpack.packb(self.to_dict(), use_bin_type=True)
        except Exception as e:
            raise ProtocolError("Failed to serialize envelope") from e

    @staticmethod
    def from_bytes(data: bytes) -> "Envelope":
        try:
            d = msgpack.unpackb(data, raw=False)
            return Envelope.from_dict(d)

        except ProtocolError:
            raise  # preserve exact failure reason

        except Exception as e:
            raise ProtocolError("Failed to deserialize envelope") from e
    # ==============================
    # Serialization (Dict / JSON)
    # ==============================

    def to_dict(self) -> dict:
        return {
            "v": self.version,
            "type": self.msg_type.value,
            "msg_id": self.msg_id,
            "sender": self.sender_id,
            "recipient": self.recipient_id,
            "ts": self.timestamp,
            "dh_pub": self.dh_pub,
            "n": self.n,
            "pn": self.pn,
            "ct": self.ciphertext,
            "nonce": self.nonce,
            "tag": self.tag,
            "ttl": self.ttl,
            "one_time": self.one_time,
            "extra": self.extra,
        }

    @staticmethod
    def from_dict(d: dict) -> "Envelope":
        try:
            if not isinstance(d, dict):
                raise ProtocolError("Envelope must be a dict")

            version = d.get("v")
            if version != 1:
                raise ProtocolError("Unsupported protocol version")

            return Envelope(
                version=version,
                msg_type=MessageType(d["type"]),
                msg_id=d["msg_id"],
                sender_id=d["sender"],
                recipient_id=d["recipient"],
                timestamp=d["ts"],
                dh_pub=d.get("dh_pub", ""),
                n=d.get("n", 0),
                pn=d.get("pn", 0),
                ciphertext=d.get("ct", b""),
                nonce=d.get("nonce", b""),
                tag=d.get("tag", b""),
                ttl=d.get("ttl"),
                one_time=d.get("one_time", False),
                extra=d.get("extra", {}),
            )

        except ProtocolError:
            raise

        except KeyError as e:
            raise ProtocolError(f"Missing field: {e}") from e

        except ValueError as e:
            raise ProtocolError("Invalid enum value") from e

        except Exception as e:
            raise ProtocolError("Invalid envelope structure") from e


# ==============================
# Validation
# ==============================

def validate(envelope: Envelope, expected_sender_id: Optional[str] = None) -> bool:
    try:
        # ---- basic types ----
        if not isinstance(envelope.version, int):
            return False

        if not isinstance(envelope.msg_type, MessageType):
            return False

        if not isinstance(envelope.msg_id, str):
            return False

        if not isinstance(envelope.sender_id, str):
            return False

        if not isinstance(envelope.recipient_id, str):
            return False

        if not isinstance(envelope.timestamp, int):
            return False

        # ---- replay protection ----
        now = int(time.time())
        if abs(now - envelope.timestamp) > 300:
            return False

        # ---- validate IDs ----
        try:
            sender_bytes = bytes.fromhex(envelope.sender_id)
            recipient_bytes = bytes.fromhex(envelope.recipient_id)
        except Exception:
            return False

        if len(sender_bytes) != 32 or len(recipient_bytes) != 32:
            return False

        # ---- sender binding ----
        if expected_sender_id is not None:
            if not utils.constant_time_compare(
                bytes.fromhex(expected_sender_id),
                sender_bytes
            ):
                return False

        # ---- CHAT validation ----
        if envelope.msg_type == MessageType.CHAT:
            if not envelope.dh_pub:
                return False

            try:
                dh_bytes = bytes.fromhex(envelope.dh_pub)
            except Exception:
                return False

            if len(dh_bytes) != 32:
                return False

            if not isinstance(envelope.n, int) or not isinstance(envelope.pn, int):
                return False

            if not (
                isinstance(envelope.ciphertext, bytes)
                and isinstance(envelope.nonce, bytes)
                and isinstance(envelope.tag, bytes)
            ):
                return False

            if len(envelope.nonce) != 12 or len(envelope.tag) != 16:
                return False

        # ---- X3DH INIT validation ----
        if envelope.msg_type == MessageType.X3DH_INIT:
            if not isinstance(envelope.extra, dict):
                return False

            required = {"identity_pubkey", "ephemeral_pubkey", "ratchet_pubkey"}
            if not required.issubset(envelope.extra.keys()):
                return False

            try:
                id_bytes = bytes.fromhex(envelope.extra["identity_pubkey"])
                eph_bytes = bytes.fromhex(envelope.extra["ephemeral_pubkey"])
            except Exception:
                return False

            if len(id_bytes) != 32 or len(eph_bytes) != 32:
                return False

        # ---- control messages ----
        if envelope.msg_type in {
            MessageType.TYPING,
            MessageType.HEARTBEAT,
            MessageType.ADDRESS_UPDATE,
            MessageType.CONSENT_REQUEST,
            MessageType.CONSENT_RESPONSE,
            MessageType.RECEIPT,
            MessageType.X3DH_ACK,
        }:
            if not isinstance(envelope.extra, dict):
                return False

        # ---- TTL ----
        if envelope.ttl is not None:
            if not isinstance(envelope.ttl, int) or envelope.ttl < 0:
                return False

        # ---- one-time ----
        if not isinstance(envelope.one_time, bool):
            return False

        return True

    except Exception:
        return False


# ==============================
# Constructors
# ==============================

def _base_envelope(sender_id: str, recipient_id: str, msg_type: MessageType) -> Envelope:
    return Envelope(
        version=1,
        msg_type=msg_type,
        msg_id=str(uuid.uuid4()),
        sender_id=sender_id,
        recipient_id=recipient_id,
        timestamp=int(time.time())
    )


def make_chat_envelope(sender_id, recipient_id, ratchet_output: dict, ttl=None, one_time=False) -> Envelope:
    return Envelope(
        version=1,
        msg_type=MessageType.CHAT,
        msg_id=str(uuid.uuid4()),
        sender_id=sender_id,
        recipient_id=recipient_id,
        timestamp=int(time.time()),
        dh_pub=ratchet_output["dh_pub"],
        n=ratchet_output["n"],
        pn=ratchet_output["pn"],
        ciphertext=ratchet_output["ciphertext"],
        nonce=ratchet_output["nonce"],
        tag=ratchet_output["tag"],
        ttl=ttl,
        one_time=one_time,
        extra={}
    )


def make_x3dh_envelope(sender_id, recipient_id, initial_message: dict) -> Envelope:
    env = _base_envelope(sender_id, recipient_id, MessageType.X3DH_INIT)
    env.extra = initial_message
    return env


def make_typing_envelope(sender_id, recipient_id) -> Envelope:
    return _base_envelope(sender_id, recipient_id, MessageType.TYPING)


def make_receipt_envelope(sender_id, recipient_id, ack_msg_id: str, status: str) -> Envelope:
    if status not in {ReceiptStatus.DELIVERED.value, ReceiptStatus.READ.value}:
        raise ProtocolError("Invalid receipt status")

    env = _base_envelope(sender_id, recipient_id, MessageType.RECEIPT)
    env.extra = {
        "ack": ack_msg_id,
        "status": status
    }
    return env
def make_x3dh_ack_envelope(sender_id, recipient_id, ratchet_pubkey: str) -> Envelope:
    env = _base_envelope(sender_id, recipient_id, MessageType.X3DH_ACK)
    env.extra = {"ratchet_pubkey": ratchet_pubkey}
    return env