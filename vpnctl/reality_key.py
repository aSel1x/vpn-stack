import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def derive_public_key(private_key_b64: str) -> str:
    """Derive a REALITY (X25519) public key from its private key.

    sing-box stores only the private key in server config; clients need the
    public key for their share links. X25519 public keys are deterministic
    functions of the private key, so this avoids ever rotating the real key.
    """
    raw_private = _b64url_decode(private_key_b64)
    private_key = X25519PrivateKey.from_private_bytes(raw_private)
    raw_public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64url_encode(raw_public)


def generate_private_key() -> str:
    """Generate a fresh REALITY (X25519) private key, sing-box's own encoding."""
    private_key = X25519PrivateKey.generate()
    raw_private = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return _b64url_encode(raw_private)
