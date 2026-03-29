# messenger/net/client.py

import asyncio
import logging
from typing import Dict, Tuple, Protocol

import websockets

from crypto.keys import IdentityKeyStore
from crypto.x3dh import X3DHInitiator, PreKeyBundle
from crypto.ratchet import DoubleRatchet, RatchetState

from net.protocol import (
    make_chat_envelope,
    make_x3dh_envelope,
    make_typing_envelope,
)


logger = logging.getLogger(__name__)


# ==============================
# Protocol typing
# ==============================

class WebSocketLike(Protocol):
    async def send(self, data: bytes): ...
    async def close(self): ...


# ==============================
# Exceptions
# ==============================

class NotConnectedError(Exception):
    pass


# ==============================
# Message Client
# ==============================

class MessageClient:

    MAX_RETRIES = 3
    BASE_DELAY = 0.5

    def __init__(self, identity_keystore: IdentityKeyStore, session_manager, bundle_provider, message_handler=None):
        self.identity_keystore = identity_keystore
        self.session_manager = session_manager
        self.bundle_provider = bundle_provider
        self.message_handler = message_handler

        self._connections: Dict[str, WebSocketLike] = {}
        self._addresses: Dict[str, Tuple[str, int]] = {}

    # ==============================
    # Connect
    # ==============================

    async def connect(self, peer_id: str, peer_address: Tuple[str, int]) -> bool:
        ip, port = peer_address
        uri = f"ws://{ip}:{port}"

        try:
            ws = await websockets.connect(uri)

            self._connections[peer_id] = ws
            self._addresses[peer_id] = peer_address

            logger.info(f"[CLIENT] Connected to {peer_id} at {uri}")

            # ---- X3DH handshake ----
            if not self.session_manager.load_session(peer_id):

                bundle_dict = self.bundle_provider.get_peer_bundle(peer_id)
                bundle = PreKeyBundle.from_dict(bundle_dict)

                initiator = X3DHInitiator(self.identity_keystore)
                shared_secret, initial_msg, alice_ratchet_priv = initiator.initiate(bundle)

                env = make_x3dh_envelope(
                    sender_id=self.identity_keystore.get_user_id(),
                    recipient_id=peer_id,
                    initial_message=initial_msg
                )

                await ws.send(env.to_bytes())

                ratchet = DoubleRatchet.from_shared_secret(
                    shared_secret,
                    their_pubkey=bundle.identity_pubkey,
                    # Bob's identity (placeholder — gets replaced on first recv DH ratchet)
                    is_initiator=True,
                    initiator_ratchet_priv=alice_ratchet_priv # ← inject keypair
                )

                self.session_manager.save_session(peer_id, ratchet)
            asyncio.create_task(self._receive_loop(peer_id, ws))
            return True

        except Exception as e:
            logger.warning(f"[CLIENT] Connection failed: {e}")
            return False

    # ==============================
    # Send Message
    # ==============================

    async def send(self, peer_id: str, plaintext: str, ttl=None, one_time=False) -> str:

        if peer_id not in self._connections:
            raise NotConnectedError(f"Not connected to {peer_id}")

        for attempt in range(self.MAX_RETRIES):

            try:
                ws = self._connections.get(peer_id)
                if not ws:
                    raise RuntimeError("Connection missing")

                ratchet = self.session_manager.load_session(peer_id)
                if not ratchet:
                    raise RuntimeError("Session missing")

                # ✅ SAFE COPY (no state mutation)
                temp_ratchet = DoubleRatchet(
                    RatchetState.from_dict(ratchet.get_state().to_dict())
                )

                ratchet_out = temp_ratchet.encrypt(plaintext.encode())

                env = make_chat_envelope(
                    sender_id=self.identity_keystore.get_user_id(),
                    recipient_id=peer_id,
                    ratchet_output=ratchet_out,
                    ttl=ttl,
                    one_time=one_time
                )

                # 🔥 SEND FIRST
                await ws.send(env.to_bytes())

                # 🔥 COMMIT ONLY AFTER SUCCESS
                self.session_manager.save_session(peer_id, temp_ratchet)

                return env.msg_id

            except Exception as e:
                logger.warning(f"[CLIENT] Send failed (attempt {attempt+1}): {e}")

                # remove stale connection ONLY (keep address)
                await self.disconnect(peer_id)

                # try reconnect
                if await self._reconnect(peer_id):
                    continue  # retry immediately

                await asyncio.sleep(self._backoff(attempt))

        raise RuntimeError("Send failed after retries")

    async def _receive_loop(self, peer_id: str, ws) -> None:
        from net.protocol import Envelope, validate, MessageType


        try:
            async for raw in ws:
                try:
                    envelope = Envelope.from_bytes(raw)

                    if not validate(envelope):
                        logger.warning("[CLIENT] Invalid envelope received")
                        continue

                    if envelope.msg_type == MessageType.CHAT:
                        ratchet = self.session_manager.load_session(peer_id)
                        if not ratchet:
                            logger.warning("[CLIENT] No session for incoming message")
                            continue

                        plaintext = ratchet.decrypt({
                            "dh_pub": envelope.dh_pub,
                            "n": envelope.n,
                            "pn": envelope.pn,
                            "ciphertext": envelope.ciphertext,
                            "nonce": envelope.nonce,
                            "tag": envelope.tag,
                        })

                        self.session_manager.save_session(peer_id, ratchet)

                        if self.message_handler:
                            await self.message_handler(
                                sender=peer_id,
                                message=plaintext,
                                msg_id=envelope.msg_id,
                                timestamp=envelope.timestamp
                            )
                    elif envelope.msg_type == MessageType.X3DH_ACK:
                        ratchet_pub_hex = envelope.extra.get("ratchet_pubkey")
                        if ratchet_pub_hex:
                            ratchet = self.session_manager.load_session(peer_id)
                            if ratchet:
                                from crypto.ratchet import _normalize_pubkey
                                ratchet.state.their_dh_pubkey = _normalize_pubkey(ratchet_pub_hex)
                                self.session_manager.save_session(peer_id, ratchet)

                    elif envelope.msg_type == MessageType.TYPING:
                        if self.message_handler:
                            await self.message_handler(sender=peer_id, typing=True)


                except Exception as e:
                    logger.warning(f"[CLIENT] Error handling incoming message: {e}")

        except Exception:
            self._connections.pop(peer_id, None)

    # ==============================
    # Typing Indicator
    # ==============================

    async def send_typing(self, peer_id: str) -> None:
        if peer_id not in self._connections:
            raise NotConnectedError(f"Not connected to {peer_id}")

        ws = self._connections[peer_id]

        env = make_typing_envelope(
            sender_id=self.identity_keystore.get_user_id(),
            recipient_id=peer_id
        )

        await ws.send(env.to_bytes())

    # ==============================
    # Disconnect
    # ==============================

    async def disconnect(self, peer_id: str) -> None:
        ws = self._connections.pop(peer_id, None)

        if ws:
            try:
                await ws.close()
            except Exception:
                pass

        # ❌ DO NOT remove address here

    async def disconnect_all(self) -> None:
        for peer_id in list(self._connections.keys()):
            await self.disconnect(peer_id)

        self._addresses.clear()

    def forget_peer(self, peer_id: str) -> None:
        self._addresses.pop(peer_id, None)

    def is_connected(self, peer_id: str) -> bool:
        return peer_id in self._connections

    # ==============================
    # Internal Helpers
    # ==============================

    async def _reconnect(self, peer_id: str) -> bool:
        if peer_id not in self._addresses:
            return False

        logger.info(f"[CLIENT] Reconnecting to {peer_id}...")

        return await self.connect(peer_id, self._addresses[peer_id])

    def _backoff(self, attempt: int) -> float:
        return self.BASE_DELAY * (2 ** attempt)