# messenger/net/server.py

import websockets
import socket
import logging
from typing import  Dict, Any

from crypto.x3dh import X3DHResponder
from crypto.ratchet import DoubleRatchet


from crypto import utils
from net.protocol import (
    Envelope, ProtocolError,
    MessageType, ReceiptStatus,
    validate, make_receipt_envelope ,make_x3dh_ack_envelope

)

logger = logging.getLogger(__name__)


class MessageServer:

    def __init__(self, host, port, message_handler, identity_keystore, session_manager, client=None):
        self.host = host or "0.0.0.0"
        self.port = port or 8765

        self.message_handler = message_handler
        self.identity_keystore = identity_keystore
        self.session_manager = session_manager
        self.client = client
        self.active_connections: Dict[str, Any] = {}
        print(f"[SERVER] Listening on {self.host}:{self.port}")

    async def start(self):
        # noinspection PyTypeChecker
        server = await websockets.serve(self._handle_connection, self.host, self.port)

        ip, port = self.get_local_address()
        logger.info(f"[SERVER] Listening on {ip}:{port}")

        await server.wait_closed()

    async def _handle_connection(self, websocket):
        peer_id = None

        try:
            raw = await websocket.recv()
            envelope = Envelope.from_bytes(raw)

            if not validate(envelope):
                raise ProtocolError("Invalid envelope")

            peer_id = envelope.sender_id

            if envelope.msg_type == MessageType.X3DH_INIT:
                await self._handle_x3dh_init(websocket, envelope)
                await self._register_connection(peer_id, websocket)

            elif envelope.msg_type == MessageType.CHAT:
                if not self.session_manager.load_session(peer_id):
                    raise ProtocolError("No session")
                await self._register_connection(peer_id, websocket)
                await self._handle_chat(envelope)

            elif envelope.msg_type == MessageType.TYPING:
                await self._register_connection(peer_id, websocket)
                await self._handle_typing(envelope)

            else:
                raise ProtocolError("Invalid initial message")

            async for raw in websocket:
                envelope = Envelope.from_bytes(raw)

                if not validate(envelope, expected_sender_id=peer_id):
                    raise ProtocolError("Validation failed")

                if envelope.msg_type == MessageType.CHAT:
                    await self._handle_chat(envelope)

                elif envelope.msg_type == MessageType.TYPING:
                    await self._handle_typing(envelope)

        except Exception as e:
            logger.exception(e)
            await websocket.close()

        finally:
            if peer_id:
                self.active_connections.pop(peer_id, None)

    async def _register_connection(self, peer_id, websocket):
        if peer_id in self.active_connections:
            await self.active_connections[peer_id].close()
        self.active_connections[peer_id] = websocket

    async def _handle_x3dh_init(self, websocket, envelope):
        if self.session_manager.load_session(envelope.sender_id):
            logger.warning(f"[SERVER] Session reset for {envelope.sender_id}")

        responder = X3DHResponder(
            self.identity_keystore,
            self.session_manager.prekey_store
        )

        shared_secret = responder.accept(envelope.extra)

        ratchet = DoubleRatchet.from_shared_secret(
            shared_secret,
            their_pubkey=envelope.extra["ratchet_pubkey"],
            is_initiator=False
        )

        self.session_manager.save_session(envelope.sender_id, ratchet)

        if self.client:
            self.client._connections[envelope.sender_id] = websocket

        # Send Bob's ratchet pubkey back so Alice can initialize their_dh_pubkey
        bob_ratchet_pub = utils.encode_pubkey(ratchet.state.sending_dh_keypair[1])

        ack = make_x3dh_ack_envelope(
            sender_id=self.identity_keystore.get_user_id(),
            recipient_id=envelope.sender_id,
            ratchet_pubkey=bob_ratchet_pub
        )
        await websocket.send(ack.to_bytes())

    async def _handle_chat(self, envelope):
        ratchet = self.session_manager.load_session(envelope.sender_id)

        plaintext = ratchet.decrypt({
            "dh_pub": envelope.dh_pub,
            "n": envelope.n,
            "pn": envelope.pn,
            "ciphertext": envelope.ciphertext,
            "nonce": envelope.nonce,
            "tag": envelope.tag,
        })

        self.session_manager.save_session(envelope.sender_id, ratchet)

        await self.message_handler(
            sender=envelope.sender_id,
            message=plaintext,
            msg_id=envelope.msg_id,
            timestamp=envelope.timestamp
        )

        ws = self.active_connections.get(envelope.sender_id)
        if ws:
            receipt = make_receipt_envelope(
                sender_id=self.identity_keystore.get_user_id(),
                recipient_id=envelope.sender_id,
                ack_msg_id=envelope.msg_id,
                status=ReceiptStatus.DELIVERED.value
            )
            await ws.send(receipt.to_bytes())

    async def _handle_typing(self, envelope):
        await self.message_handler(sender=envelope.sender_id, typing=True)

    def get_local_address(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0], self.port
        except:
            return "127.0.0.1", self.port