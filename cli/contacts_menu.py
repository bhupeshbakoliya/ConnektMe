import asyncio
import json
from crypto.x3dh import create_prekey_bundle


async def _ainput(prompt: str) -> str:
    """Non-blocking input — keeps the event loop free."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


class ContactsMenu:

    def __init__(self, ctx):
        self.ctx = ctx

    # -------------------------
    # SAFE SHORT ID DISPLAY
    # -------------------------
    def _display_id(self, pubkey, contacts):
        short = pubkey[:8]
        matches = [c for c in contacts if c["pubkey"].startswith(short)]
        if len(matches) > 1:
            return pubkey[:12]
        return short

    # -------------------------
    # LIST CONTACTS
    # -------------------------
    def list_contacts(self):
        contacts = self.ctx.contacts_repo.list_contacts()

        print("\n--- Contacts ---")
        if not contacts:
            print("No contacts saved.")
            return []

        for i, c in enumerate(contacts, 1):
            display_id = self._display_id(c["pubkey"], contacts)
            print(f"{i}. {c['nickname']} ({display_id})")

        return contacts

    # -------------------------
    # ADD CONTACT
    # -------------------------
    async def add_contact(self):
        print("\n--- Add Contact ---")

        pubkey = (await _ainput("Enter full ID: ")).strip()
        nickname = (await _ainput("Nickname: ")).strip()
        ip = (await _ainput("IP: ")).strip()

        if ip.lower().startswith("ip:"):
            ip = ip.split(":", 1)[1].strip()

        if ip == "0.0.0.0":
            print("❌ Invalid IP. Use 127.0.0.1 for local testing.")
            return

        if ":" in ip:
            ip, port_str = ip.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                print("❌ Invalid port")
                return
        else:
            try:
                port = int((await _ainput("Port: ")).strip())
            except ValueError:
                print("❌ Invalid port")
                return

        try:
            self.ctx.contacts_repo.add_contact(pubkey, nickname, ip, port)
            print("✅ Contact added")
        except Exception as e:
            print(f"❌ {e}")

    # -------------------------
    # EXPORT MY BUNDLE
    # -------------------------
    def export_bundle(self):
        try:
            bundle = create_prekey_bundle(
                self.ctx.keystore,
                self.ctx.session_manager.prekey_store
            )

            user_id = self.ctx.keystore.get_user_id()
            short_id = user_id[:8]
            path = f"bundle_{short_id}.json"

            with open(path, "w") as f:
                json.dump(bundle.to_dict(), f, indent=2)

            print(f"✅ Bundle exported → {path}")

        except Exception as e:
            print(f"❌ Failed to export bundle: {e}")

    # -------------------------
    # IMPORT PEER BUNDLE
    # -------------------------
    async def import_bundle(self):
        try:
            peer_id = (await _ainput("Enter FULL peer ID: ")).strip()
            path = (await _ainput("Bundle path: ")).strip()

            with open(path, "r") as f:
                bundle = json.load(f)

            self.ctx.client.bundle_provider.register(peer_id, bundle)
            print("✅ Bundle imported")

        except Exception as e:
            print(f"❌ Failed to import bundle: {e}")