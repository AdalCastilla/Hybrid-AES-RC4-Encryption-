"""The four encryption schemes compared in HW4 Part 3.

AES-256 and RC4 come from the team's Part 1 (aes.py) and Part 2 (rc4.py) code.
The only addition is `aes_encrypt_with_nonce`, which builds the same
nonce || tag || ciphertext blob as aes.py:encrypt_file but takes the
nonce as an argument. Fixing the nonce inside a comparison pair is what
aes.py:file_avalanche already does, and it is required for the
Avalanche Effect, because otherwise a fresh random nonce alone would change
about half of the output bits.
"""

import base64
import binascii
from dataclasses import dataclass
from typing import Callable

from Crypto.Cipher import AES

from aes import decrypt_file as aes_decrypt
from aes import encrypt_file as aes_encrypt_random_nonce
from rc4 import rc4_decrypt, rc4_encrypt

AES_KEY_BYTES = 32  # AES-256
HEADER_BYTES = 32  # 16-byte EAX nonce + 16-byte tag, as stored by aes.py


def aes_key(text_or_bytes) -> bytes:
    """Turn a paper key such as "universitas" into a 256-bit AES key.

    Short keys are right-padded with NUL bytes, which is what PHP's
    openssl_encrypt (used by Atikah et al.) does with a short key. Unlike
    hashing the key, padding keeps a one-character change in the text key
    a small change in the AES key, so the experiment stays faithful.
    """
    raw = text_or_bytes.encode() if isinstance(text_or_bytes, str) else bytes(text_or_bytes)
    if len(raw) > AES_KEY_BYTES:
        raise ValueError("AES-256 key longer than 32 bytes")
    return raw.ljust(AES_KEY_BYTES, b"\x00")


def rc4_key(text_or_bytes) -> bytes:
    return text_or_bytes.encode() if isinstance(text_or_bytes, str) else bytes(text_or_bytes)


def aes_encrypt_with_nonce(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


def aes_decrypt_unverified(blob: bytes, key: bytes) -> bytes:
    """Decrypt without checking the tag. Only used to show what an attacker
    would get if the receiver ignored authentication."""
    nonce, ciphertext = blob[:16], blob[HEADER_BYTES:]
    return AES.new(key, AES.MODE_EAX, nonce=nonce).decrypt(ciphertext)


@dataclass(frozen=True)
class Scheme:
    name: str
    uses_aes: bool
    uses_rc4: bool
    # encrypt(data, aes_key, rc4_key, nonce); nonce=None means a random nonce.
    encrypt: Callable[[bytes, bytes, bytes, bytes | None], bytes]
    decrypt: Callable[[bytes, bytes, bytes], bytes]


def _aes(data: bytes, key: bytes, nonce: bytes | None) -> bytes:
    if nonce is None:
        return aes_encrypt_random_nonce(data, key)
    return aes_encrypt_with_nonce(data, key, nonce)


SCHEMES: list[Scheme] = [
    Scheme(
        "AES only", True, False,
        lambda d, ka, kr, n: _aes(d, ka, n),
        lambda c, ka, kr: aes_decrypt(c, ka),
    ),
    Scheme(
        "RC4 only", False, True,
        lambda d, ka, kr, n: rc4_encrypt(d, kr),
        lambda c, ka, kr: rc4_decrypt(c, kr),
    ),
    Scheme(
        # The paper's proposed method (Fig. 1 and Fig. 2).
        "AES-RC4", True, True,
        lambda d, ka, kr, n: rc4_encrypt(_aes(d, ka, n), kr),
        lambda c, ka, kr: aes_decrypt(rc4_decrypt(c, kr), ka),
    ),
    Scheme(
        "RC4-AES", True, True,
        lambda d, ka, kr, n: _aes(rc4_encrypt(d, kr), ka, n),
        lambda c, ka, kr: rc4_decrypt(aes_decrypt(c, ka), kr),
    ),
]

SCHEME_BY_NAME = {s.name: s for s in SCHEMES}


# Paper-faithful variant: PHP's openssl_encrypt returns Base64 text by
# default, so the AES stage of the original web application produced
# Base64 characters rather than raw bytes.
def b64(data: bytes) -> bytes:
    return base64.b64encode(data)


BASE64_SCHEMES: dict[str, Callable[[bytes, bytes, bytes, bytes], bytes]] = {
    "AES only": lambda d, ka, kr, n: b64(aes_encrypt_with_nonce(d, ka, n)),
    "RC4 only": lambda d, ka, kr, n: rc4_encrypt(d, kr),
    "AES-RC4": lambda d, ka, kr, n: rc4_encrypt(b64(aes_encrypt_with_nonce(d, ka, n)), kr),
    "RC4-AES": lambda d, ka, kr, n: b64(aes_encrypt_with_nonce(rc4_encrypt(d, kr), ka, n)),
}


# Other output representations tried for the proposed AES-RC4 scheme, to see
# whether any of them gives the ~58% Avalanche Effect reported in the paper.
# All start from the PHP-style pipeline: Base64 AES output, then RC4.
def _php_aes_rc4(d: bytes, ka: bytes, kr: bytes, n: bytes) -> bytes:
    return rc4_encrypt(b64(aes_encrypt_with_nonce(d, ka, n)), kr)


AES_RC4_ENCODINGS: dict[str, Callable[[bytes, bytes, bytes, bytes], bytes]] = {
    "Hexadecimal of RC4 output": lambda d, ka, kr, n: binascii.hexlify(_php_aes_rc4(d, ka, kr, n)),
    "Base64 of RC4 output": lambda d, ka, kr, n: b64(_php_aes_rc4(d, ka, kr, n)),
    # Each RC4 byte read as a Latin-1 character and written as UTF-8. The
    # length then depends on the data, so the AE uses the common length.
    "UTF-8 of RC4 bytes": lambda d, ka, kr, n: _php_aes_rc4(d, ka, kr, n).decode("latin-1").encode("utf-8"),
}


def bit_difference(first: bytes, second: bytes) -> int:
    if len(first) != len(second):
        raise ValueError("Inputs must have equal length")
    return int.from_bytes(first, "big").__xor__(int.from_bytes(second, "big")).bit_count()
