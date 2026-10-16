"""Verschlüsselte Dateicontainer (.smf) mit denselben Verfahren wie Textnachrichten.

Aufbau einer .smf-Datei:
    b"SMF1" + Kennung (3 Byte ASCII) | 16 Byte Salt | 12 Byte Nonce | AES-GCM-Ciphertext

Kopf (Magic + Kennung) ist unverschlüsselt, damit die Kennung erkannt werden
kann, wird aber als authentifizierte Zusatzdaten mitgeschützt.

Klartext im Inneren:
    4 Byte Länge (big endian) | JSON-Verzeichnis [{"name": ..., "size": ...}, ...] | Dateiinhalte
Dateinamen sind damit verschlüsselt; nach außen ist nur die Gesamtgröße sichtbar.
"""
import json
import os
import struct
import unicodedata
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securemessage.crypto import LABEL_RE, _key

MAGIC = b"SMF1"
HEADER_LEN = len(MAGIC) + 3
SALT_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FILES = 1000
MAX_NAME_LEN = 255
_INDEX_LEN = struct.Struct(">I")
_FORBIDDEN_NAME_CHARS = set('/\\:*?"<>|')
_RESERVED_WINDOWS = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                     *(f"LPT{i}" for i in range(1, 10))}


@dataclass(frozen=True)
class PlainFile:
    name: str
    data: bytes


def check_name(name: str) -> str:
    """Erlaubt nur einfache Dateinamen ohne Pfadanteile (Schutz beim Speichern)."""
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_LEN:
        raise ValueError("Ungültiger Dateiname.")
    if name in (".", "..") or name != name.strip() or name.endswith("."):
        raise ValueError("Ungültiger Dateiname.")
    if any(ch in _FORBIDDEN_NAME_CHARS or unicodedata.category(ch)[0] == "C" for ch in name):
        raise ValueError("Ungültiger Dateiname.")
    if name.split(".")[0].upper() in _RESERVED_WINDOWS:
        raise ValueError("Ungültiger Dateiname.")
    return name


def is_smf(head: bytes) -> bool:
    return head[:len(MAGIC)] == MAGIC


def extract_file_label(data: bytes) -> str:
    if len(data) < HEADER_LEN or not is_smf(data):
        raise ValueError("Keine SecureMessage-Datei (.smf).")
    label = data[len(MAGIC):HEADER_LEN].decode("ascii", errors="replace")
    if not LABEL_RE.fullmatch(label):
        raise ValueError("Keine gültige Kennung in der .smf-Datei.")
    return label


def encrypt_files(label: str, password: str, files: list[PlainFile]) -> bytes:
    if not LABEL_RE.fullmatch(label):
        raise ValueError("Ungültige Kennung (A01 bis E20).")
    if not files:
        raise ValueError("Keine Dateien ausgewählt.")
    if len(files) > MAX_FILES:
        raise ValueError(f"Zu viele Dateien (höchstens {MAX_FILES}).")
    names = [check_name(f.name) for f in files]
    if len({n.casefold() for n in names}) != len(names):
        raise ValueError("Mehrere Dateien mit gleichem Namen.")
    if sum(len(f.data) for f in files) > MAX_TOTAL_BYTES:
        raise ValueError("Dateien sind zusammen größer als 200 MB.")

    index = json.dumps([{"name": f.name, "size": len(f.data)} for f in files],
                       ensure_ascii=False).encode("utf-8")
    plaintext = b"".join([_INDEX_LEN.pack(len(index)), index, *(f.data for f in files)])
    header = MAGIC + label.encode("ascii")
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    return header + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, plaintext, header)


def decrypt_files(data: bytes, password: str) -> list[PlainFile]:
    extract_file_label(data)
    if len(data) < HEADER_LEN + SALT_LEN + NONCE_LEN + TAG_LEN:
        raise ValueError("Datei ist unvollständig.")
    if len(data) > MAX_TOTAL_BYTES + 16 * 1024 * 1024:
        raise ValueError("Datei ist zu groß.")
    header = data[:HEADER_LEN]
    salt = data[HEADER_LEN:HEADER_LEN + SALT_LEN]
    nonce = data[HEADER_LEN + SALT_LEN:HEADER_LEN + SALT_LEN + NONCE_LEN]
    try:
        plaintext = AESGCM(_key(password, salt)).decrypt(
            nonce, data[HEADER_LEN + SALT_LEN + NONCE_LEN:], header)
    except Exception as exc:
        raise ValueError("Entschlüsselung fehlgeschlagen: Passwort falsch "
                         "oder Datei beschädigt.") from exc
    return _unpack(plaintext)


def _unpack(plaintext: bytes) -> list[PlainFile]:
    # Inhalt ist authentifiziert; die Prüfungen schützen trotzdem vor
    # fehlerhaft erzeugten Containern (Defense in Depth).
    broken = ValueError("Dateiinhalt ist ungültig.")
    if len(plaintext) < _INDEX_LEN.size:
        raise broken
    (index_len,) = _INDEX_LEN.unpack_from(plaintext)
    start = _INDEX_LEN.size + index_len
    if start > len(plaintext):
        raise broken
    try:
        index = json.loads(plaintext[_INDEX_LEN.size:start].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise broken from None
    if not isinstance(index, list) or not 0 < len(index) <= MAX_FILES:
        raise broken
    files, pos, seen = [], start, set()
    for entry in index:
        if not isinstance(entry, dict) or set(entry) != {"name", "size"}:
            raise broken
        name, size = check_name(entry["name"]), entry["size"]
        if type(size) is not int or size < 0 or pos + size > len(plaintext):
            raise broken
        if name.casefold() in seen:
            raise broken
        seen.add(name.casefold())
        files.append(PlainFile(name, plaintext[pos:pos + size]))
        pos += size
    if pos != len(plaintext):
        raise broken
    return files
