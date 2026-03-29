from crypto.x3dh import create_prekey_bundle
import json

class CommandHandler:
    def __init__(self, ctx):
        self.ctx = ctx

    async def handle(self, line: str):
        if line == "/quit":
            await self.ctx.client.disconnect_all()
            raise SystemExit

        elif line == "/id":
            print(self.ctx.my_id)

        elif line == "/export-bundle":
            await self._export_bundle()

        else:
            print("Unknown command")

    async def _export_bundle(self):
        bundle = create_prekey_bundle(
            self.ctx.keystore,
            self.ctx.prekey_store
        )
        path = self.ctx.data_dir / "bundle.json"

        with open(path, "w") as f:
            json.dump(bundle.to_dict(), f, indent=2)

        print(f"Bundle exported → {path}")