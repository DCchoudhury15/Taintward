"""FF1 against the official NIST sample vectors (FF1samples.pdf, Samples 1-9)."""

from __future__ import annotations

import random
import unittest

from sdk.ff1 import FF1, min_len

K128 = "2B7E151628AED2A6ABF7158809CF4F3C"
K192 = K128 + "EF4359D8D580AA4F"
# Note: the NIST AES-256 sample key is not the 192-bit key plus 8 bytes;
# its last 16 hex digits are 7F036D6F04FC6A94.
K256 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"
T10 = "39383736353433323130"
T11 = "3737373770717273373737"
PT10 = "0123456789"
PT36 = "0123456789abcdefghi"

# (sample, key, radix, tweak hex, plaintext, ciphertext)
NIST_SAMPLES = [
    (1, K128, 10, "", PT10, "2433477484"),
    (2, K128, 10, T10, PT10, "6124200773"),
    (3, K128, 36, T11, PT36, "a9tv40mll9kdu509eum"),
    (4, K192, 10, "", PT10, "2830668132"),
    (5, K192, 10, T10, PT10, "2496655549"),
    (6, K192, 36, T11, PT36, "xbj3kv35jrawxv32ysr"),
    (7, K256, 10, "", PT10, "6657667009"),
    (8, K256, 10, T10, PT10, "1001623463"),
    (9, K256, 36, T11, PT36, "xs8a0azh2avyalyzuwd"),
]


class TestFF1NistVectors(unittest.TestCase):
    def test_nist_samples_encrypt_and_decrypt(self):
        for sample, key, radix, tweak, pt, ct in NIST_SAMPLES:
            with self.subTest(sample=sample):
                c = FF1(bytes.fromhex(key), radix)
                tw = bytes.fromhex(tweak)
                self.assertEqual(c.encrypt(pt, tw), ct)
                self.assertEqual(c.decrypt(ct, tw), pt)


class TestFF1Properties(unittest.TestCase):
    def test_round_trip_many_lengths_and_radixes(self):
        rng = random.Random(1234)
        key = bytes.fromhex(K256)
        for radix in (2, 10, 26, 36, 62, 256, 65536):
            c = FF1(key, radix)
            for n in range(c.min_len, c.min_len + 25):
                x = [rng.randrange(radix) for _ in range(n)]
                tw = bytes(rng.randrange(256) for _ in range(rng.randrange(20)))
                y = c.encrypt_numerals(x, tw)
                self.assertEqual(len(y), n)
                self.assertEqual(c.decrypt_numerals(y, tw), x)

    def test_tweak_changes_output(self):
        c = FF1(bytes.fromhex(K128), 10)
        self.assertNotEqual(c.encrypt(PT10, b""), c.encrypt(PT10, b"x"))

    def test_minimum_domain_size_enforced(self):
        self.assertEqual(min_len(10), 6)   # 10**6 = 1,000,000
        self.assertEqual(min_len(36), 4)   # 36**4 = 1,679,616
        self.assertEqual(min_len(2), 20)   # 2**20 = 1,048,576
        c = FF1(bytes.fromhex(K128), 10)
        with self.assertRaises(ValueError):
            c.encrypt("12345")
        self.assertEqual(len(c.encrypt("123456")), 6)

    def test_bad_inputs_rejected(self):
        with self.assertRaises(ValueError):
            FF1(b"short", 10)
        with self.assertRaises(ValueError):
            FF1(bytes(16), 1)
        c = FF1(bytes(16), 10)
        with self.assertRaises(ValueError):
            c.encrypt("12345a")  # 'a' is not a radix-10 numeral


if __name__ == "__main__":
    unittest.main()
