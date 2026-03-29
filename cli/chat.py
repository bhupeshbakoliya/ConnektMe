import asyncio


async def _ainput(prompt: str) -> str:
    """Non-blocking input — keeps receive loop alive while waiting for user input."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


class ChatUI:

    def __init__(self, ctx):
        self.ctx = ctx

    async def start_chat(self, contact):
        peer_id = contact["pubkey"]
        ip = contact["local_ip"].strip()
        port = int(contact["port"])

        if ip == "0.0.0.0":
            print("⚠️  Stored IP is invalid (0.0.0.0). Using 127.0.0.1 instead.")
            ip = "127.0.0.1"

        print(f"\n[DEBUG] Connecting to {ip}:{port}")
        print(f"Connecting to {contact['nickname']}...")

        ok = await self.ctx.client.connect(peer_id, (ip, port))

        if not ok:
            print("❌ Connection failed")
            return

        print("✅ Connected!")
        print("Type /exit to leave chat\n")

        while True:
            msg = await _ainput("you > ")

            if msg == "/exit":
                return

            try:
                await self.ctx.client.send(peer_id, msg)
            except Exception as e:
                print(f"Send failed: {e}")