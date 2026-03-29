import asyncio
import argparse
from pathlib import Path

from db.store import Database
from db.contacts import ContactsRepository

from core.session import InMemorySessionManager
from core.bundle import LocalBundleProvider
from core.context import AppContext

from cli.menu import Menu

from crypto.keys import IdentityKeyStore
from crypto.x3dh import PreKeyStore

from net.client import MessageClient
from net.server import MessageServer


async def on_message(sender, message=None, msg_id=None, timestamp=None, typing=False):
    if typing:
        print(f"\n[{sender[:12]}] typing...")
    else:
        print(f"\n[{sender[:12]}]: {message.decode()} ({timestamp})")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=str, default="data/default")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    # DB
    db = Database(data_dir / "messages.db")
    db.connect()
    db.initialize_schema()

    # Identity
    keystore = IdentityKeyStore(data_dir)
    keystore.initialize()

    # Crypto — must generate prekeys or X3DH handshake will fail
    prekey_store = PreKeyStore()
    with keystore.use_signing_key() as signing_priv:
        prekey_store.generate_signed_prekey(signing_priv)
    prekey_store.generate_prekeys(10)

    session_manager = InMemorySessionManager(prekey_store)
    bundle_provider = LocalBundleProvider()

    # Network
    client = MessageClient(
        identity_keystore=keystore,
        session_manager=session_manager,
        bundle_provider=bundle_provider,
        message_handler=on_message
    )

    server = MessageServer(
        host="0.0.0.0",
        port=args.port,
        message_handler=on_message,
        identity_keystore=keystore,
        session_manager=session_manager,
        client=client
    )

    # Context
    ctx = AppContext(keystore, client, server, session_manager, db)
    ctx.contacts_repo = ContactsRepository(db)

    # Start server — create_task schedules it; sleep yields so it binds before menu runs
    asyncio.create_task(server.start())
    await asyncio.sleep(0.2)

    print(f"\n[DATA DIR] {data_dir}")
    print(f"[USER ID]  {keystore.get_user_id()}\n")

    menu = Menu(ctx)
    await menu.main_menu()


if __name__ == "__main__":
    asyncio.run(main())