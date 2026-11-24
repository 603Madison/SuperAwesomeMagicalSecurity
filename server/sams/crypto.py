"""Signing of server -> agent/probe instructions.

Agents run as root and probes scan the internet, so anything the server tells
them to do is signed with an Ed25519 key. Agents/probes pin the public key at
enrollment time; a compromised network path (or a spoofed server) cannot
inject patch tasks or point a probe at third-party targets.

Wire format (``SignedEnvelope``)::

    {"payload": "<base64 of exact JSON bytes>", "signature": "<base64 ed25519 sig over those bytes>",
     "key_id": "<first 16 hex of sha256(pubkey)>"}

Verifiers check the signature over the *decoded payload bytes* and only then
parse the JSON, so no canonicalization rules need to agree across languages.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self.public_key_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(self.public_key_raw).hexdigest()[:16]

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_raw).decode()

    @classmethod
    def load_or_create(cls, path: str | Path) -> "Signer":
        p = Path(path)
        if p.exists():
            sk = serialization.load_pem_private_key(p.read_bytes(), password=None)
            assert isinstance(sk, Ed25519PrivateKey)
            return cls(sk)
        p.parent.mkdir(parents=True, exist_ok=True)
        sk = Ed25519PrivateKey.generate()
        pem = sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return cls(sk)

    @classmethod
    def ephemeral(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    def sign(self, payload: dict[str, Any]) -> dict[str, str]:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode()
        sig = self._sk.sign(raw)
        return {"payload": base64.b64encode(raw).decode(), "signature": base64.b64encode(sig).decode(),
                "key_id": self.key_id}


def verify(envelope: dict[str, str], public_key_b64: str) -> dict[str, Any]:
    """Verify an envelope and return the decoded payload. Raises ValueError on failure."""
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        raw = base64.b64decode(envelope["payload"])
        pk.verify(base64.b64decode(envelope["signature"]), raw)
    except Exception as exc:  # cryptography raises InvalidSignature, binascii errors, KeyError...
        raise ValueError(f"invalid signature: {exc}") from exc
    return json.loads(raw)
