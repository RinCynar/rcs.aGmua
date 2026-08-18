"""Local key and history storage with legacy file compatibility."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from .core import bytes_to_hex, encrypt_text, rc4_transform, utf16_bytes, decrypt_text

DEFAULT_KEY = "DEF-4164E792FC9AD1C9C866B3D6DCC79A27"
DATA_FOLDER = ".aGmua"
VERSIONED_PREFIX = b"v2:"


def application_data_dir() -> Path:
    """Choose a writable directory for CLI, desktop and Android builds."""

    override = os.environ.get("RCS_AGMUA_DATA_DIR")
    if override:
        return Path(override).expanduser()

    flet_storage = os.environ.get("FLET_APP_STORAGE_DATA")
    if flet_storage:
        return Path(flet_storage) / DATA_FOLDER

    return Path.cwd() / DATA_FOLDER


class Vault:
    """A username-scoped collection of keys and encrypted history."""

    def __init__(self, username: str, data_dir: Path | None = None) -> None:
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty")
        self.username = username
        self.data_dir = data_dir or application_data_dir()
        self.keys = [DEFAULT_KEY]

    @property
    def identity(self) -> str:
        username_bytes = utf16_bytes(self.username)
        return bytes_to_hex(rc4_transform(username_bytes, username_bytes))

    @property
    def key_file(self) -> Path:
        return self.data_dir / f"{self.identity}.rcs_keys"

    @property
    def history_file(self) -> Path:
        return self.data_dir / f"{self.identity}.rcs_hst"

    def ensure_files(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.key_file.exists():
            self.save_keys()
        if not self.history_file.exists():
            self.history_file.write_bytes(b"")

    def _decode_line(self, line: bytes) -> str:
        if line.startswith(VERSIONED_PREFIX):
            encrypted = base64.b64decode(line[len(VERSIONED_PREFIX) :], validate=True)
        else:
            encrypted = line
        return decrypt_text(self.username, encrypted)

    def _encode_line(self, value: str) -> bytes:
        encrypted = encrypt_text(self.username, value)
        encoded = base64.b64encode(encrypted)
        return VERSIONED_PREFIX + encoded + b"\n"

    def load_keys(self) -> list[str]:
        self.keys = [DEFAULT_KEY]
        if not self.key_file.exists():
            return self.keys

        for line_number, line in enumerate(self.key_file.read_bytes().splitlines()):
            if not line:
                continue
            try:
                decoded = self._decode_line(line).strip()
            except (UnicodeError, ValueError, base64.binascii.Error):
                continue

            # Old releases wrote the username as the first line and then
            # accidentally loaded it as a custom key.  Skip both forms.
            if line_number == 0 and decoded == self.username:
                continue
            if decoded in ("", DEFAULT_KEY, self.username):
                continue
            if decoded not in self.keys:
                self.keys.append(decoded)
        return self.keys

    def save_keys(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        custom_keys = [
            key for key in self.keys if key not in (DEFAULT_KEY, self.username)
        ]
        payload = [self._encode_line(self.username)]
        payload.extend(self._encode_line(key) for key in custom_keys)
        self.key_file.write_bytes(b"".join(payload))

    def add_key(self, key: str) -> bool:
        key = key.strip()
        if not key or key in self.keys:
            return False
        self.keys.append(key)
        self.save_keys()
        return True

    def delete_key(self, index: int) -> str:
        if index < 0 or index >= len(self.keys):
            raise IndexError("Key index is out of range")
        if self.keys[index] == DEFAULT_KEY:
            raise ValueError("The default key cannot be deleted")
        deleted = self.keys.pop(index)
        self.save_keys()
        return deleted

    def reset(self) -> None:
        for path in (self.key_file, self.history_file):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        self.keys = [DEFAULT_KEY]
        self.save_keys()
        self.history_file.write_bytes(b"")

    def save_history(self, record: str) -> None:
        self.ensure_files()
        with self.history_file.open("ab") as handle:
            handle.write(self._encode_line(record))

    def history(self) -> list[str]:
        if not self.history_file.exists():
            return []
        records: list[str] = []
        for line in self.history_file.read_bytes().splitlines():
            if not line:
                continue
            try:
                record = self._decode_line(line)
            except (UnicodeError, ValueError, base64.binascii.Error):
                # Legacy raw ciphertext could contain newline bytes.  Invalid
                # fragments are ignored instead of making all history unreadable.
                continue
            if record != self.username:
                records.append(record.rstrip("\x00"))
        return records

    def clear_history(self) -> None:
        try:
            self.history_file.unlink()
        except FileNotFoundError:
            return
        self.history_file.write_bytes(b"")

