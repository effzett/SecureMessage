"""Versioned, authenticated password-based message encryption."""
import base64
import json
import os
import re
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LABEL_RE = re.compile(r"^[A-E](?:0[1-9]|1[0-9]|20)$")
PREFIX = "SM1"
MEMORY_KIB = 65536
ITERATIONS = 3
PARALLELISM = 1
MAX_MESSAGE_BYTES = 1024 * 1024
# Unsichtbare Zeichen, die Messenger beim Kopieren einfügen und die
# str.split() nicht als Leerraum erkennt.
_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"))


def _key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Passwort fehlt.")
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost=ITERATIONS,
                           memory_cost=MEMORY_KIB, parallelism=PARALLELISM,
                           hash_len=32, type=Type.ID)


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(data: str) -> bytes:
    decoded = base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)
    if _encode(decoded) != data:
        raise ValueError("Nicht-kanonische Base64-Kodierung.")
    return decoded


def encrypt(label: str, password: str, plaintext: str) -> str:
    if not LABEL_RE.fullmatch(label):
        raise ValueError("Ungültige Kennung (A01 bis E20).")
    raw = plaintext.encode("utf-8")
    if not raw:
        raise ValueError("Nachricht ist leer.")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("Nachricht ist zu lang.")
    salt, nonce = os.urandom(16), os.urandom(12)
    aad = f"{PREFIX}:{label}".encode("ascii")
    ciphertext = AESGCM(_key(password, salt)).encrypt(nonce, raw, aad)
    return f"{PREFIX}:{label}:{_encode(salt + nonce + ciphertext)}"


def normalize(message: str) -> str:
    """Entfernt Leerraum und unsichtbare Zeichen (z. B. Umbrüche aus WhatsApp).

    Das SM1-Format enthält davon nie etwas, daher kann keine gültige
    Nachricht verfälscht werden; Manipulationen erkennt weiterhin AES-GCM.
    """
    return "".join(message.translate(_INVISIBLE).split())


def extract_label(message: str) -> str:
    parts = normalize(message).split(":", 2)
    if len(parts) != 3 or parts[0] != PREFIX or not LABEL_RE.fullmatch(parts[1]):
        raise ValueError("Kein gültiges SecureMessage-Format (SM1).")
    return parts[1]


def decrypt(message: str, password: str) -> str:
    message = normalize(message)
    label = extract_label(message)
    payload = message.split(":", 2)[2]
    if len(payload) > 2 * MAX_MESSAGE_BYTES + 256:
        raise ValueError("Nachricht ist zu lang.")
    try:
        data = _decode(payload)
        if len(data) < 44:
            raise ValueError("Daten unvollständig.")
        salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
        plaintext = AESGCM(_key(password, salt)).decrypt(nonce, ciphertext,
                                                        f"{PREFIX}:{label}".encode("ascii"))
        return plaintext.decode("utf-8")
    except (ValueError, UnicodeDecodeError, Exception) as exc:
        # Do not expose crypto implementation details to the GUI.
        raise ValueError("Entschlüsselung fehlgeschlagen: Passwort falsch oder Nachricht beschädigt.") from exc
