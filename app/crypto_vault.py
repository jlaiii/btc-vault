"""Secret storage.

The hot wallet seed and every TOTP secret are encrypted at rest with
AES-256-GCM. The master key lives in a file OUTSIDE the database, so a
stolen database dump (backup, SQL injection, disk image) is useless without
also compromising the container's secret mount.

Format of a sealed value:  base64( nonce(12) || ciphertext || tag(16) )
"""

import base64
import os
import secrets as pysecrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# BIP39 → the hot wallet seed. 24 words = 256 bits of entropy.
SEED_WORDS = 24


class VaultError(RuntimeError):
    pass


def _load_master_key(path: str) -> bytes:
    if not os.path.exists(path):
        raise VaultError(
            f"Master key not found at {path}. The wallet cannot decrypt its seed "
            f"without it. Run the setup script (scripts/setup.sh) to create it."
        )
    raw = open(path, "rb").read().strip()
    # accept 64 hex chars, or base64, or raw 32 bytes
    try:
        if len(raw) == 64 and all(c in b"0123456789abcdefABCDEF" for c in raw):
            key = bytes.fromhex(raw.decode())
        else:
            key = base64.b64decode(raw, validate=True)
    except Exception:
        key = raw
    if len(key) != 32:
        raise VaultError(
            f"Master key at {path} must be 32 bytes (64 hex chars); found {len(key)} bytes."
        )
    return key


class Vault:
    """Encrypt/decrypt small secrets with AES-256-GCM."""

    def __init__(self, key_path: str):
        self.key_path = key_path
        self._key = _load_master_key(key_path)
        self._aes = AESGCM(self._key)

    def seal_str(self, plaintext: str) -> str:
        nonce = pysecrets.token_bytes(12)
        blob = self._aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + blob).decode("ascii")

    def open_str(self, sealed: str) -> str:
        try:
            raw = base64.b64decode(sealed, validate=True)
        except Exception as exc:
            raise VaultError("Stored secret is not valid base64.") from exc
        if len(raw) < 29:
            raise VaultError("Stored secret is truncated.")
        try:
            return self._aes.decrypt(raw[:12], raw[12:], None).decode("utf-8")
        except InvalidTag as exc:
            raise VaultError(
                "Could not decrypt stored secret — the master key does not match "
                "the one used to encrypt it."
            ) from exc

    @staticmethod
    def generate_master_key_hex() -> str:
        return pysecrets.token_hex(32)
