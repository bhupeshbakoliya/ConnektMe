# messenger/crypto/utils.py

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, constant_time, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


# ==============================
# Custom Exception
# ==============================

class CryptoError(Exception):
    """Base exception for all crypto-related failures."""
    pass


# ==============================
# Key Generation
# ==============================

def generate_keypair():
    try:
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        raise CryptoError(f"Key generation failed")


# ==============================
# Diffie-Hellman
# ==============================

def dh(private_key, public_key) -> bytes:
    try:
        return private_key.exchange(public_key)
    except Exception:
        raise CryptoError("DH exchange failed")


# ==============================
# HKDF (SHA-256)
# ==============================

def hkdf(input_key_material: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    try:
        hkdf_obj = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf_obj.derive(input_key_material)
    except Exception:
        raise CryptoError("HKDF derivation failed")


# ==============================
# AES-256-GCM Encryption
# ==============================

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes):
    try:
        if len(key) != 32:
            raise CryptoError("AES key must be 32 bytes")

        aes = AESGCM(key)
        nonce = os.urandom(12)

        encrypted = aes.encrypt(nonce, plaintext, associated_data)

        # Split ciphertext and tag
        ciphertext = encrypted[:-16]
        tag = encrypted[-16:]

        return ciphertext, nonce, tag

    except CryptoError:
        raise
    except Exception:
        raise CryptoError("AES-GCM encryption failed")


# ==============================
# AES-256-GCM Decryption
# ==============================

def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes) -> bytes:
    try:
        if len(key) != 32:
            raise CryptoError("AES key must be 32 bytes")

        aes = AESGCM(key)
        combined = ciphertext + tag

        return aes.decrypt(nonce, combined, associated_data)

    except CryptoError:
        raise
    except Exception:
        # Do not leak failure reason (important for security)
        raise CryptoError("AES-GCM decryption failed")


# ==============================
# Key Encoding / Decoding
# ==============================

def encode_pubkey(public_key) -> str:
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
    except Exception:
        raise CryptoError("Public key encoding failed")


def decode_pubkey(hex_str: str):
    try:
        raw = bytes.fromhex(hex_str)
        return x25519.X25519PublicKey.from_public_bytes(raw)
    except Exception:
        raise CryptoError("Public key decoding failed")


def encode_privkey(private_key) -> bytes:
    try:
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception:
        raise CryptoError("Private key encoding failed")


def decode_privkey(raw_bytes: bytes):
    try:
        return x25519.X25519PrivateKey.from_private_bytes(raw_bytes)
    except Exception:
        raise CryptoError("Private key decoding failed")


# ==============================
# Constant-Time Compare
# ==============================

def constant_time_compare(a: bytes, b: bytes) -> bool:
    try:
        return constant_time.bytes_eq(a, b)
    except Exception:
        raise CryptoError("Constant-time comparison failed")