"""FF1 format-preserving encryption (NIST SP 800-38G, Algorithm 7 and 8).

FF1 is the FPE mode NIST still approves (FF3 and FF3-1 were withdrawn in
the SP 800-38G Rev.1 draft, Feb 2025). This is a direct, small
implementation on top of AES from the ``cryptography`` package. It is
checked against the official NIST FF1 sample vectors in tests/test_ff1.py.

Supported:
  * AES-128 / 192 / 256 keys (16, 24 or 32 bytes)
  * any radix from 2 to 65536 (numeral-list API), and radix 2..36 for the
    string API using the alphabet 0-9 then a-z
  * any tweak length up to ``MAX_TWEAK_LEN`` bytes (empty tweak allowed)
  * message length from ``min_len(radix)`` up to 2**32 - 1 numerals

Domain size: the spec requires radix**minlen >= 1,000,000. Inputs shorter
than that raise ``ValueError``; the caller decides what to do with them
(taintward/sdk/redact.py masks them, see docs/redaction-crypto.md).

This module does not pick or store keys. Key management is the caller's job.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
MIN_DOMAIN = 1_000_000
MAX_LEN = 2**32 - 1
MAX_TWEAK_LEN = 2**32 - 1
_ROUNDS = 10


def min_len(radix: int) -> int:
    """Smallest message length allowed for this radix (radix**n >= 1e6)."""
    if not 2 <= radix <= 65536:
        raise ValueError("radix must be in 2..65536")
    n = 2
    while radix**n < MIN_DOMAIN:
        n += 1
    return n


def _num(numerals: list[int], radix: int) -> int:
    x = 0
    for d in numerals:
        x = x * radix + d
    return x


def _str(x: int, radix: int, m: int) -> list[int]:
    out = [0] * m
    for i in range(m - 1, -1, -1):
        x, out[i] = divmod(x, radix)
    return out


class FF1:
    """FF1 cipher for one (key, radix) pair. Tweak is given per call."""

    def __init__(self, key: bytes, radix: int = 10):
        if len(key) not in (16, 24, 32):
            raise ValueError("FF1 key must be 16, 24 or 32 bytes (AES-128/192/256)")
        if not 2 <= radix <= 65536:
            raise ValueError("radix must be in 2..65536")
        self.radix = radix
        self.min_len = min_len(radix)
        # ECB on single blocks is the AES block function CIPH_K from the spec.
        self._aes = Cipher(algorithms.AES(key), modes.ECB())

    # --- core algorithm on numeral lists ---

    def _check(self, x: list[int], tweak: bytes) -> None:
        n = len(x)
        if n < self.min_len or n > MAX_LEN:
            raise ValueError(
                f"FF1 length {n} outside {self.min_len}..{MAX_LEN} for radix {self.radix}"
            )
        if len(tweak) > MAX_TWEAK_LEN:
            raise ValueError("tweak too long")
        for d in x:
            if not 0 <= d < self.radix:
                raise ValueError("numeral out of range for radix")

    def _setup(self, n: int, t: int):
        u = n // 2
        v = n - u
        # b = ceil(ceil(v * log2(radix)) / 8), computed exactly with integers.
        b = ((self.radix**v - 1).bit_length() + 7) // 8
        d = 4 * ((b + 3) // 4) + 4
        p = (
            bytes([1, 2, 1])
            + self.radix.to_bytes(3, "big")
            + bytes([10, u % 256])
            + n.to_bytes(4, "big")
            + t.to_bytes(4, "big")
        )
        return u, v, b, d, p

    def _round_value(self, enc, p: bytes, tweak: bytes, i: int, b_num: int,
                     b: int, d: int) -> int:
        """y = NUM(S) for round i, where S is derived from PRF(P || Q)."""
        t = len(tweak)
        q = tweak + bytes((-t - b - 1) % 16) + bytes([i]) + b_num.to_bytes(b, "big")
        msg = p + q
        # PRF = CBC-MAC with zero IV: keep only the last block.
        r = bytes(16)
        for off in range(0, len(msg), 16):
            blk = bytes(a ^ c for a, c in zip(r, msg[off:off + 16]))
            r = enc.update(blk)
        s = r
        j = 1
        while len(s) < d:
            blk = (int.from_bytes(r, "big") ^ j).to_bytes(16, "big")
            s += enc.update(blk)
            j += 1
        return int.from_bytes(s[:d], "big")

    def encrypt_numerals(self, x: list[int], tweak: bytes = b"") -> list[int]:
        self._check(x, tweak)
        n = len(x)
        u, v, b, d, p = self._setup(n, len(tweak))
        a, bb = list(x[:u]), list(x[u:])
        enc = self._aes.encryptor()
        for i in range(_ROUNDS):
            y = self._round_value(enc, p, tweak, i, _num(bb, self.radix), b, d)
            m = u if i % 2 == 0 else v
            c = (_num(a, self.radix) + y) % (self.radix**m)
            a, bb = bb, _str(c, self.radix, m)
        return a + bb

    def decrypt_numerals(self, x: list[int], tweak: bytes = b"") -> list[int]:
        self._check(x, tweak)
        n = len(x)
        u, v, b, d, p = self._setup(n, len(tweak))
        a, bb = list(x[:u]), list(x[u:])
        enc = self._aes.encryptor()
        for i in range(_ROUNDS - 1, -1, -1):
            y = self._round_value(enc, p, tweak, i, _num(a, self.radix), b, d)
            m = u if i % 2 == 0 else v
            c = (_num(bb, self.radix) - y) % (self.radix**m)
            a, bb = _str(c, self.radix, m), a
        return a + bb

    # --- string API (radix <= 36, alphabet 0-9a-z) ---

    def _to_numerals(self, s: str) -> list[int]:
        if self.radix > len(ALPHABET):
            raise ValueError("string API supports radix up to 36; use *_numerals")
        try:
            out = [ALPHABET.index(c) for c in s]
        except ValueError:
            raise ValueError("character outside the 0-9a-z alphabet") from None
        if any(d >= self.radix for d in out):
            raise ValueError("character outside the alphabet for this radix")
        return out

    def encrypt(self, s: str, tweak: bytes = b"") -> str:
        return "".join(ALPHABET[d] for d in self.encrypt_numerals(self._to_numerals(s), tweak))

    def decrypt(self, s: str, tweak: bytes = b"") -> str:
        return "".join(ALPHABET[d] for d in self.decrypt_numerals(self._to_numerals(s), tweak))
