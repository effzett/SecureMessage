import unittest

from securemessage.crypto import decrypt, encrypt, extract_label, normalize

PASSWORD = "Testpasswort123!"


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.message = encrypt("D12", PASSWORD, "Treffen um 10 Uhr")

    def test_line_breaks_and_spaces_are_ignored(self):
        broken = f"  {self.message[:15]}\n{self.message[15:40]}\r\n {self.message[40:]}\t"
        self.assertEqual(decrypt(broken, PASSWORD), "Treffen um 10 Uhr")

    def test_invisible_characters_are_ignored(self):
        broken = self.message[:10] + "​" + self.message[10:30] + " " + self.message[30:] + "﻿"
        self.assertEqual(extract_label(broken), "D12")
        self.assertEqual(decrypt(broken, PASSWORD), "Treffen um 10 Uhr")

    def test_normalize_keeps_valid_message_unchanged(self):
        self.assertEqual(normalize(self.message), self.message)

    def test_tampering_still_detected(self):
        tampered = self.message[:-3] + ("A" if self.message[-3] != "A" else "B") + self.message[-2:]
        with self.assertRaises(ValueError):
            decrypt(tampered, PASSWORD)


if __name__ == "__main__":
    unittest.main()
