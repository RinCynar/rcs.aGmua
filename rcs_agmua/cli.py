"""Pure Python interactive command-line client."""

from __future__ import annotations

import argparse

from . import __version__
from .core import bytes_to_hex, encrypt_text, hex_to_bytes, decrypt_text
from .storage import DEFAULT_KEY, Vault
from .updates import check_for_updates


def print_help() -> None:
    print(
        """
Commands:
  <text>           Encrypt text
  - <hex>          Decrypt text with all saved keys
  - <hex> -<num>   Decrypt text with one key
  rak <key>        Add a key
  rdk -<num>       Delete a key
  rck              Display saved keys
  rsh              Show history
  rch              Clear history
  res              Restore default configuration
  rcu              Check for updates
  relp             Display this help
  rxit             Exit RCS

The legacy brute-force command has been removed.
""".strip()
    )


def _encrypt(vault: Vault, plaintext: str) -> None:
    print("Available keys:")
    for index, key in enumerate(vault.keys):
        print(f"  {index}: {key[:3]}")
    selected = input("Key number (default 0): ").strip() or "0"
    try:
        index = int(selected)
        key = vault.keys[index]
    except (ValueError, IndexError):
        print("Invalid key number; using the default key.")
        key = DEFAULT_KEY
    ciphertext = bytes_to_hex(encrypt_text(key, plaintext))
    print(f"Encrypted text: {ciphertext}")
    vault.save_history(f"Encrypted text: {ciphertext} with key {key[:3]}")


def _decrypt(vault: Vault, command: str) -> None:
    parts = command.split()
    if len(parts) < 2:
        print("Format: - <hex> [-<key number>]")
        return
    try:
        ciphertext = hex_to_bytes(parts[1])
        selected = [vault.keys[int(parts[2][1:])]] if len(parts) > 2 else vault.keys
    except (ValueError, IndexError):
        print("Invalid ciphertext or key number.")
        return

    for key in selected:
        try:
            plaintext = decrypt_text(key, ciphertext)
            result = f"Decrypted text with key {key[:3]}: {plaintext}"
        except (UnicodeError, ValueError):
            result = f"Decryption failed with key {key[:3]}"
        print(result)
        vault.save_history(result)


def _updates() -> None:
    release = check_for_updates()
    if release is None:
        print("Update check failed. Check the network or the project Releases page.")
        return
    if release.is_newer:
        print(f"A newer version {release.version} is available: {release.url}")
    else:
        print(f"You are using the latest version ({__version__}).")


def interactive_mode() -> None:
    print(f"RCS.aGmua {__version__} - RC4 text tool")
    username = input("Username: ").strip()
    try:
        vault = Vault(username)
    except ValueError as error:
        print(error)
        return
    vault.ensure_files()
    vault.load_keys()

    while True:
        try:
            command = input("\n>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not command:
            continue
        if command.lower() == "rxit":
            return
        if command.lower() == "relp":
            print_help()
        elif command.startswith("rak "):
            print("Key added." if vault.add_key(command[4:]) else "Key already exists or is empty.")
        elif command.startswith("rdk"):
            parts = command.split()
            try:
                deleted = vault.delete_key(int(parts[1].lstrip("-")))
                print(f"Key deleted: {deleted}")
            except (ValueError, IndexError):
                print("Invalid key number or the default key cannot be deleted.")
        elif command.lower() == "rck":
            for index, key in enumerate(vault.keys):
                print(f"{index}: {key}")
        elif command.lower() == "rsh":
            records = vault.history()
            print("\n".join(records) if records else "No history records found.")
        elif command.lower() == "rch":
            vault.clear_history()
            print("History cleared.")
        elif command.lower() == "res":
            vault.reset()
            print("Default configuration restored.")
        elif command.lower() == "rcu":
            _updates()
        elif command.startswith("- "):
            _decrypt(vault, command)
        else:
            _encrypt(vault, command)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RCS.aGmua RC4 text tool")
    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if args.interactive:
        interactive_mode()
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

