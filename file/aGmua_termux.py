#!//data/data/com.termux/files/usr/bin/env
import sys
import os
import itertools
import requests
from arc4 import ARC4

DEFAULT_KEY = "DEF-4164E792FC9AD1C9C866B3D6DCC79A27"
KEYS = [DEFAULT_KEY]
RCS_FOLDER = ".aGmua"
KEY_FILE_TEMPLATE = os.path.join(RCS_FOLDER, "{}.rcs_keys")
HISTORY_FILE_TEMPLATE = os.path.join(RCS_FOLDER, "{}.rcs_hst")
OPT_FILE = "aGmua_opt.md"
RCS_VER = 1.91
DOWNLOAD_LINK = "https://aGmua.us.kg/file/aGmua_termux.py"
UPDATE_URL = "http://aGmua.us.kg"

username = ""


def print_message(message):
    print("\n" + message + "\n")


def get_input(prompt, default=None):
    user_input = input(prompt).strip()
    return user_input if user_input else default


def load_keys():
    global KEYS, username
    key_file = KEY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    try:
        with open(key_file, "rb") as file:
            encrypted_keys = file.readlines()
            for line in encrypted_keys:
                decrypted_line = rc4_decrypt(
                    username.encode("utf-16"), line.strip()
                ).decode("utf-16")
                if decrypted_line.strip() != DEFAULT_KEY:
                    KEYS.append(decrypted_line.strip())
    except FileNotFoundError:
        KEYS = [DEFAULT_KEY]


def save_keys():
    key_file = KEY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    with open(key_file, "wb") as file:
        encrypted_username = (
            rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")) + b"\n"
        )
        file.write(encrypted_username)
        for key in KEYS:
            if key != DEFAULT_KEY:
                encrypted_key = (
                    rc4_encrypt(username.encode("utf-16"), key.encode("utf-16")) + b"\n"
                )
                file.write(encrypted_key)


def reset():
    global KEYS
    try:
        os.remove(
            HISTORY_FILE_TEMPLATE.format(
                bytes_to_hex(
                    rc4_encrypt(username.encode("utf-16"), username.encode("utf-16"))
                )
            )
        )
        os.remove(
            KEY_FILE_TEMPLATE.format(
                bytes_to_hex(
                    rc4_encrypt(username.encode("utf-16"), username.encode("utf-16"))
                )
            )
        )
    except FileNotFoundError:
        pass
    KEYS = [DEFAULT_KEY]
    save_keys()
    print_message("Restoring default configuration completed.")


def add_key(new_key):
    global KEYS
    if new_key not in KEYS:
        KEYS.append(new_key)
        save_keys()
        print_message(f"Key added: {new_key}")
    else:
        print_message(f"Key '{new_key}' already exists.")


def delete_key(key_number):
    global KEYS
    try:
        key_number = int(key_number)
        if 0 <= key_number < len(KEYS):
            if KEYS[key_number] == DEFAULT_KEY:
                print_message("Cannot delete the default key.")
            else:
                deleted_key = KEYS.pop(key_number)
                save_keys()
                print_message(f"Key deleted: {deleted_key}")
        else:
            print_message(f"Invalid key number: {key_number}")
    except ValueError:
        print_message(f"Invalid key number: {key_number}")


def utf16_to_bytes(s):
    return s.encode("utf-16")


def rc4_encrypt(key, plaintext):
    cipher = ARC4(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def rc4_decrypt(key, ciphertext):
    cipher = ARC4(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def bytes_to_hex(b):
    return b.hex().upper()


def hex_to_bytes(h):
    return bytes.fromhex(h)


def choose_key_for_encryption():
    global KEYS
    print_message("Available keys for encryption:")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key[:3]}")

    choice = get_input("Choose a key number (default is 0): ", "0")
    try:
        index = int(choice)
        if 0 <= index < len(KEYS):
            return KEYS[index]
        else:
            raise ValueError
    except ValueError:
        print_message("Invalid choice, using default key.")
        return KEYS[0]


def choose_key_for_decryption():
    global KEYS
    print_message("Trying keys in order:")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key[:3]}")
    return KEYS


def save_history(record):
    encrypted_record = rc4_encrypt(username.encode("utf-16"), record.encode("utf-16"))
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    with open(history_file, "ab") as file:
        file.write(encrypted_record + b"\n")


def display_history():
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    try:
        with open(history_file, "rb") as file:
            history = file.readlines()
            if not history:
                print_message("No history records found.")
            else:
                for line in history:
                    try:
                        decrypted_line = rc4_decrypt(
                            username.encode("utf-16"), line.strip()
                        )
                        print(decrypted_line.decode("utf-16").rstrip("\x00"))
                        print("")
                    except Exception as e:
                        print_message(f"Error decrypting history record: {str(e)}")
    except FileNotFoundError:
        print_message("No history records found.")


def clear_history():
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    try:
        os.remove(history_file)
        print_message("History records cleared.")
    except FileNotFoundError:
        print_message("No history records to clear.")


def extract_version_and_link(update_info):
    parts = update_info.split(" ")
    version_str = parts[2]
    download_link = parts[-1]
    return version_str, download_link


def check_for_updates():
    try:
        response = requests.get(UPDATE_URL)
        response.raise_for_status()
        update_info = response.text.strip()
        version_str, download_link = extract_version_and_link(update_info)
        latest_version = float(version_str)
        return latest_version, download_link
    except requests.RequestException:
        return None, None


def handle_command(user_input):
    global username
    if user_input.lower() == "rxit":
        return False
    elif user_input.lower() == "relp":
        print_help()
    elif user_input.startswith("rak"):
        if len(user_input.split()) > 1:
            new_key = user_input.split(" ", 1)[1]
            add_key(new_key)
        else:
            print_message("Invalid input format for rak command.")
    elif user_input.startswith("rdk"):
        parts = user_input.split()
        if len(parts) == 2 and parts[0] == "rdk" and parts[1].startswith("-"):
            key_number = parts[1][1:]
            delete_key(key_number)
        else:
            print_message(
                "Invalid input format for rdk command. Format should be: rdk -<key_number>"
            )
    elif user_input.lower() == "res":
        reset()
    elif user_input.lower() == "rck":
        display_keys()
        print("")
    elif user_input.startswith("rc "):
        if len(user_input.split()) > 1:
            text_to_crack = user_input.split(" ", 1)[1]
            bruteforce_decrypt(text_to_crack)
        else:
            print_message("Invalid input format for rc command.")
    elif user_input.lower() == "rsh":
        display_history()
    elif user_input.lower() == "rch":
        clear_history()
    elif user_input.lower() == "rcu":
        try:
            latest_version, download_link = check_for_updates()
            if latest_version > RCS_VER:
                print(
                    f"A newer version {latest_version} is available. Download it from {download_link}."
                )
            else:
                print("You are using the latest version.")
        except Exception:
            print(
                "Failed to check for updates. If there haven't any network problems, please view https://aGmua.us.kg"
            )
    elif user_input.startswith("- "):
        decrypt_text(user_input)
    else:
        encrypt_text(user_input)
    return True


def interactive_mode():
    global username

    print_message(
        f"aGmua {RCS_VER}, a text encryption tool based on RC4 encryption algorithm\nhttp://rincynar.us.kg, RinCynar\nType 'relp' for usage instructions"
    )

    username = get_input("Enter your username: ")
    key_file = KEY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )

    if not os.path.exists(RCS_FOLDER):
        os.mkdir(RCS_FOLDER)

    if not os.path.exists(key_file):
        encrypted_username = (
            rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")) + b"\n"
        )
        with open(key_file, "wb") as file:
            file.write(encrypted_username)

    if not os.path.exists(history_file):
        encrypted_username = (
            rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")) + b"\n"
        )
        with open(history_file, "wb") as file:
            file.write(encrypted_username)

    load_keys()

    while True:
        user_input = input("\n>> ").strip()
        if not user_input:
            continue
        if not handle_command(user_input):
            break

def print_help():
    print(
        """
Commands:
<text>           Encrypt <text>
- <text>         Decrypt <text>
rxit             Exit RCS
relp             Display this help message
rak <key>        Add a Key
rdk -<num>       Delete a Key
res              Restore
rck              Display Current Keys
rc <text>        Crack the text
rsh              Show History
rch              Clear History
rcu              Check for Updates
        """
    )

def display_keys():
    global username
    print_message("Current keys:")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key}")


def decrypt_text(user_input):
    global KEYS, username
    parts = user_input.split(" ")
    if len(parts) < 2:
        print_message("Invalid input format.")
        return

    text = parts[1]
    key_number = int(parts[2][1:]) if len(parts) > 2 else None

    if key_number is not None:
        if 0 <= key_number < len(KEYS):
            keys_to_try = [KEYS[key_number]]
        else:
            print_message(f"Invalid key number: {key_number}")
            return
    else:
        keys_to_try = KEYS

    ciphertext_bytes = hex_to_bytes(text)
    decryption_results = []

    for key in keys_to_try:
        try:
            key_bytes = utf16_to_bytes(key)
            plaintext_bytes = rc4_decrypt(key_bytes, ciphertext_bytes)
            decrypted_text = plaintext_bytes.decode("utf-16")
            decryption_results.append(
                f"Decrypted text with key {key[:3]}: {decrypted_text}"
            )
        except Exception as e:
            decryption_results.append(f"Decryption failed with key {key[:3]}")
            continue

    for result in decryption_results:
        print_message(result)
        save_history(result)


def encrypt_text(plaintext):
    global KEYS, username
    key = choose_key_for_encryption()
    key_bytes = utf16_to_bytes(key)
    plaintext_bytes = utf16_to_bytes(plaintext)
    ciphertext_bytes = rc4_encrypt(key_bytes, plaintext_bytes)
    ciphertext_hex = bytes_to_hex(ciphertext_bytes)
    print_message(f"Encrypted text: {ciphertext_hex}")
    save_history(f"Encrypted text: {ciphertext_hex} with key {key[:3]}")


def bruteforce_decrypt(ciphertext):
    global username
    character_set = "`~!@#$%^&*()-=_+[]\\{}|;':\",./<>?0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    min_length = int(input("Enter minimum key length: "))
    max_length = int(input("Enter maximum key length: "))

    with open(OPT_FILE, "w") as output_file:
        for length in range(min_length, max_length + 1):
            print(f"Trying keys of length {length}...")
            for attempt in itertools.product(character_set, repeat=length):
                key = "".join(attempt)
                try:
                    decrypted_text = rc4_decrypt(
                        utf16_to_bytes(key), hex_to_bytes(ciphertext)
                    )
                    decrypted_text = decrypted_text.decode("utf-16").rstrip("\x00")
                    output_file.write(f"Key: {key}, Decrypted text: {decrypted_text}\n")
                except Exception as e:
                    continue

    print("Bruteforce decryption completed. Results saved in rcs_opt.md\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "-i":
        interactive_mode()
    else:
        print("Usage: aGmua -i for interactive mode")
