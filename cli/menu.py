import asyncio
from cli.contacts_menu import ContactsMenu
from cli.chat import ChatUI


async def _ainput(prompt: str) -> str:
    """Non-blocking input — keeps the event loop free for server/receive tasks."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


class Menu:

    def __init__(self, ctx):
        self.ctx = ctx
        self.contacts_ui = ContactsMenu(ctx)
        self.chat_ui = ChatUI(ctx)

    async def main_menu(self):
        while True:
            print("\n==== ConnektMe ====")
            print("1. My ID")
            print("2. Contacts")
            print("3. Start Chat")
            print("4. Exit")

            choice = await _ainput("> ")

            if choice == "1":
                self.show_id()
            elif choice == "2":
                await self._contacts_menu()
            elif choice == "3":
                await self.chat_menu()
            elif choice == "4":
                print("Bye.")
                return
            else:
                print("Invalid choice")

    def show_id(self):
        uid = self.ctx.keystore.get_user_id()
        print(f"\nYour ID:\n{uid}")

    # -------------------------
    # CONTACTS MENU
    # -------------------------
    async def _contacts_menu(self):
        while True:
            print("\n--- Contacts ---")
            print("1. List contacts")
            print("2. Add contact")
            print("3. Export my bundle")
            print("4. Import peer bundle")
            print("5. Back")

            choice = await _ainput("> ")

            if choice == "1":
                self.contacts_ui.list_contacts()
            elif choice == "2":
                await self.contacts_ui.add_contact()
            elif choice == "3":
                self.contacts_ui.export_bundle()
            elif choice == "4":
                await self.contacts_ui.import_bundle()
            elif choice == "5":
                return
            else:
                print("Invalid option")

    # -------------------------
    # CHAT MENU
    # -------------------------
    async def chat_menu(self):
        contacts = self.contacts_ui.list_contacts()

        if not contacts:
            print("No contacts found.")
            return

        print("\nSelect contact:")
        for i, c in enumerate(contacts, 1):
            print(f"{i}. {c['nickname']} ({c['pubkey'][:8]})")

        choice = await _ainput("> ")

        try:
            contact = contacts[int(choice) - 1]
        except Exception:
            print("Invalid selection")
            return

        await self.chat_ui.start_chat(contact)