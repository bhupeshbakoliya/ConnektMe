from pathlib import Path
import os
import subprocess
from contextlib import contextmanager

from cryptography.hazmat.primitives.asymmetric import ed25519

from crypto import utils
from crypto.utils import CryptoError


# ==============================
# Exceptions
# ==============================

class KeyStoreError(Exception):
    pass


class KeyLoadError(KeyStoreError):
    pass


class KeyNotInitializedError(KeyStoreError):
    pass


# ==============================
# Helpers
# ==============================

def _atomic_write(path: Path, data: bytes):
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, path)


# ==============================
# Identity Key Store
# ==============================

class IdentityKeyStore:

    FILE_VERSION = b"\x01"
    SECRET_AAD = b"machine-secret-v1"
    IDENTITY_AAD = b"identity-key"
    SIGNING_AAD = b"signing-key"

    def __init__(self, data_dir: Path):
        self.key_path = data_dir / "identity.key"
        self.secret_path = data_dir / "machine.secret"
        self.signing_path = data_dir / "signing.key"

        self._private_key = None
        self._public_key = None

        self._signing_private = None
        self._signing_public = None

        self._initialized = False

        if ".git" in str(data_dir.resolve()):
            print("[WARNING] Storing secrets inside a git repository is unsafe")

    # ==============================
    # Public API
    # ==============================

    def initialize(self) -> None:
        try:
            if self.key_path.exists():
                if not self.secret_path.exists() or not self.signing_path.exists():
                    raise KeyStoreError(
                        "Incomplete key directory — missing machine.secret or signing.key"
                    )
                self._load()
            else:
                self._generate()
                self._save()

            self._initialized = True

        except KeyStoreError:
            raise
        except Exception as e:
            raise KeyStoreError(f"Initialization failed: {e}")

    def get_public_key(self):
        self._ensure_initialized()
        return self._public_key

    def get_signing_public_key(self):
        self._ensure_initialized()
        return self._signing_public

    def get_user_id(self) -> str:
        self._ensure_initialized()
        return utils.encode_pubkey(self._public_key)

    def get_fingerprint(self) -> str:
        uid = self.get_user_id()
        return " ".join(uid[i:i+8] for i in range(0, len(uid), 8))

    def export_bundle(self) -> dict:
        self._ensure_initialized()
        return {
            "id": self.get_user_id(),
            "dh_pub": utils.encode_pubkey(self._public_key),
            "sign_pub": self._signing_public.public_bytes_raw().hex()
        }

    # ==============================
    # Controlled Private Access
    # ==============================

    @contextmanager
    def use_private_key(self):
        self._ensure_initialized()
        yield self._private_key

    @contextmanager
    def use_signing_key(self):
        self._ensure_initialized()
        yield self._signing_private

    # ==============================
    # Internal Methods
    # ==============================

    def _generate(self):
        try:
            priv, pub = utils.generate_keypair()
            self._private_key = priv
            self._public_key = pub

            sign_priv = ed25519.Ed25519PrivateKey.generate()
            sign_pub = sign_priv.public_key()

            self._signing_private = sign_priv
            self._signing_public = sign_pub

        except Exception as e:
            raise KeyStoreError(f"Key generation failed: {e}")

    def _save(self):
        try:
            key = self._derive_local_key()

            # ---------- Identity Key ----------
            raw_priv = utils.encode_privkey(self._private_key)

            ct, nonce, tag = utils.aes_gcm_encrypt(
                key, raw_priv, associated_data=self.IDENTITY_AAD
            )

            blob = self.FILE_VERSION + nonce + tag + ct

            os.makedirs(self.key_path.parent, exist_ok=True)
            _atomic_write(self.key_path, blob)
            os.chmod(self.key_path, 0o600)

            # ---------- Signing Key ----------
            raw_sign = self._signing_private.private_bytes_raw()

            ct, nonce, tag = utils.aes_gcm_encrypt(
                key, raw_sign, associated_data=self.SIGNING_AAD
            )

            blob = self.FILE_VERSION + nonce + tag + ct

            _atomic_write(self.signing_path, blob)
            os.chmod(self.signing_path, 0o600)

            # Only validation, no creation
            if self._is_tracked(self.secret_path):
                print("[WARNING] machine.secret is tracked by git!")

        except Exception as e:
            raise KeyStoreError(f"Key save failed: {e}")

    def _load(self):
        try:
            key = self._derive_local_key()

            # ---------- Identity Key ----------
            data = self.key_path.read_bytes()

            if len(data) < 1 + 12 + 16:
                raise KeyLoadError("Corrupted identity key file")

            version = data[:1]
            if version != self.FILE_VERSION:
                raise KeyLoadError("Unsupported identity key version")

            nonce = data[1:13]
            tag = data[13:29]
            ciphertext = data[29:]

            raw_priv = utils.aes_gcm_decrypt(
                key, ciphertext, nonce, tag, associated_data=self.IDENTITY_AAD
            )

            priv = utils.decode_privkey(raw_priv)
            self._private_key = priv
            self._public_key = priv.public_key()

            # ---------- Signing Key ----------
            data = self.signing_path.read_bytes()

            if len(data) < 1 + 12 + 16:
                raise KeyLoadError("Corrupted signing key file")

            version = data[:1]
            if version != self.FILE_VERSION:
                raise KeyLoadError("Unsupported signing key version")

            nonce = data[1:13]
            tag = data[13:29]
            ciphertext = data[29:]

            raw_sign = utils.aes_gcm_decrypt(
                key, ciphertext, nonce, tag, associated_data=self.SIGNING_AAD
            )

            self._signing_private = ed25519.Ed25519PrivateKey.from_private_bytes(raw_sign)
            self._signing_public = self._signing_private.public_key()

        except CryptoError:
            raise KeyLoadError("Failed to decrypt key material")
        except Exception as e:
            raise KeyLoadError(f"Key load failed: {e}")

    def _derive_local_key(self) -> bytes:
        secret = self._get_or_create_machine_secret()

        return utils.hkdf(
            input_key_material=secret,
            length=32,
            salt=b"connektme-local-salt",
            info=b"keystore-encryption"
        )

    def _get_or_create_machine_secret(self) -> bytes:
        if self.secret_path.exists():
            data = self.secret_path.read_bytes()

            if len(data) != 32:
                raise KeyLoadError("Invalid machine secret length")

            return data

        secret = os.urandom(32)

        os.makedirs(self.secret_path.parent, exist_ok=True)
        _atomic_write(self.secret_path, secret)
        os.chmod(self.secret_path, 0o600)

        return secret

    def _ensure_initialized(self):
        if not self._initialized:
            raise KeyNotInitializedError("KeyStore not initialized")

    @staticmethod
    def _is_tracked(path: Path) -> bool:
        try:
            result = subprocess.run(
                ["git", "ls-files", "--error-unmatch", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except Exception:
            return False