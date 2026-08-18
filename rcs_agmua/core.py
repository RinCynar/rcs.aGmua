"""Compatibility implementation of the project's legacy RC4 text format."""

from __future__ import annotations


def rc4_transform(key: bytes, data: bytes) -> bytes:
    """Apply the RC4 stream transform.

    RCS.aGmua historically used a fresh ``arc4.ARC4`` instance for every
    operation.  Keeping the implementation here removes the native package
    dependency while preserving that byte-for-byte behavior.
    """

    if not key:
        raise ValueError("RC4 requires a non-empty key")

    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    output = bytearray(len(data))
    i = 0
    j = 0
    for position, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        stream_byte = state[(state[i] + state[j]) & 0xFF]
        output[position] = value ^ stream_byte
    return bytes(output)


def utf16_bytes(value: str) -> bytes:
    """Return the legacy Python ``utf-16`` representation, including BOM."""

    return value.encode("utf-16")


def utf16_text(value: bytes) -> str:
    return value.decode("utf-16")


def encrypt_text(key: str, plaintext: str) -> bytes:
    return rc4_transform(utf16_bytes(key), utf16_bytes(plaintext))


def decrypt_text(key: str, ciphertext: bytes) -> str:
    return utf16_text(rc4_transform(utf16_bytes(key), ciphertext))


def bytes_to_hex(value: bytes) -> str:
    return value.hex().upper()


def hex_to_bytes(value: str) -> bytes:
    compact = "".join(value.split())
    if not compact or len(compact) % 2:
        raise ValueError("Ciphertext must contain an even number of hex digits")
    return bytes.fromhex(compact)

