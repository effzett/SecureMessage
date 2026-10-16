import json
import os
import struct
import unittest

from securemessage import filecrypto
from securemessage.filecrypto import (
    MAX_TOTAL_BYTES, PlainFile, check_name, decrypt_files, encrypt_files, extract_file_label,
)

PW = "Papier-Passwort 1"


class FileCryptoTests(unittest.TestCase):
    def test_roundtrip_multiple_files(self):
        files = [PlainFile("Bericht.pdf", os.urandom(5000)),
                 PlainFile("Foto äöü.jpg", os.urandom(12345)),
                 PlainFile("leer.txt", b"")]
        blob = encrypt_files("E20", PW, files)
        self.assertEqual(extract_file_label(blob), "E20")
        self.assertEqual(decrypt_files(blob, PW), files)

    def test_file_names_are_not_visible(self):
        blob = encrypt_files("A01", PW, [PlainFile("Geheimplan.docx", b"x" * 100)])
        self.assertNotIn(b"Geheimplan", blob)

    def test_wrong_password_rejected(self):
        blob = encrypt_files("A01", PW, [PlainFile("a.txt", b"hallo")])
        with self.assertRaises(ValueError):
            decrypt_files(blob, "falsch")

    def test_tampering_rejected(self):
        blob = bytearray(encrypt_files("A01", PW, [PlainFile("a.txt", b"hallo")]))
        blob[-1] ^= 1
        with self.assertRaises(ValueError):
            decrypt_files(bytes(blob), PW)

    def test_label_swap_rejected(self):
        blob = encrypt_files("A01", PW, [PlainFile("a.txt", b"hallo")])
        with self.assertRaises(ValueError):
            decrypt_files(blob.replace(b"SMF1A01", b"SMF1A02", 1), PW)

    def test_not_an_smf_file(self):
        with self.assertRaises(ValueError):
            extract_file_label(b"%PDF-1.7 irgendwas")

    def test_size_limit(self):
        big = PlainFile("gross.bin", bytes(MAX_TOTAL_BYTES + 1))
        with self.assertRaises(ValueError):
            encrypt_files("A01", PW, [big])

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_files("A01", PW, [PlainFile("a.txt", b"1"), PlainFile("A.TXT", b"2")])


class NameCheckTests(unittest.TestCase):
    def test_valid_names(self):
        for name in ["a.txt", "Foto 2026-10-17.jpg", "Übersicht (final).xlsx", ".profil"]:
            self.assertEqual(check_name(name), name)

    def test_dangerous_names_rejected(self):
        for name in ["", ".", "..", "../x.txt", "ordner/x.txt", "..\\x.txt", "C:x.txt",
                     "a\x00b", "zeile\numbruch", " vorne", "hinten ", "punkt.",
                     "CON", "nul.txt", "x" * 256]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_name(name)

    def test_malicious_container_rejected(self):
        # Gültig verschlüsselter Container mit Pfad im Namen darf nicht entpackt werden.
        index = json.dumps([{"name": "../../evil.sh", "size": 3}]).encode()
        plaintext = struct.pack(">I", len(index)) + index + b"rm!"
        with self.assertRaises(ValueError):
            filecrypto._unpack(plaintext)

    def test_inconsistent_sizes_rejected(self):
        index = json.dumps([{"name": "a.txt", "size": 10}]).encode()
        with self.assertRaises(ValueError):
            filecrypto._unpack(struct.pack(">I", len(index)) + index + b"zu kurz")
        with self.assertRaises(ValueError):
            filecrypto._unpack(struct.pack(">I", len(index)) + index + b"viel zu lang!!")


if __name__ == "__main__":
    unittest.main()
