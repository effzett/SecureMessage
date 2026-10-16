import unittest
from securemessage.crypto import encrypt, decrypt


class CanonicalEncodingTests(unittest.TestCase):
    def test_noncanonical_last_character_rejected(self):
        # Construct a ciphertext whose Base64 payload has unused trailing bits.
        for n in range(4):
            message = encrypt("B19", "Testpasswort123!", "X" * (n + 1))
            prefix, label, payload = message.split(":", 2)
            if len(payload) % 4 in (2, 3):
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                index = alphabet.index(payload[-1])
                alternate = alphabet[index ^ 1]
                tampered = f"{prefix}:{label}:{payload[:-1]}{alternate}"
                with self.assertRaises(ValueError):
                    decrypt(tampered, "Testpasswort123!")
                return
        self.fail("Could not construct noncanonical Base64 test case")
