# Manajemen penyimpanan data lokal di sisi klien.
#
# Setiap username memiliki file lokal sendiri:
#   client/local_users/<username-terenkode>.json
#
# File lokal menyimpan:
#   - local share terenkripsi + nonce
#   - salt KDF + parameter KDF
#   - backup vault lokal terenkripsi + nonce
#   - username sebagai metadata
#
# Recovery share tidak disimpan oleh aplikasi.

from __future__ import annotations

import base64
import json
import os
from urllib.parse import quote


LOCAL_DATA_FILENAME = "local_data.json"  # legacy single-user file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_USERS_DIR = os.path.join(BASE_DIR, "local_users")
LOCAL_DATA_PATH = os.path.join(BASE_DIR, LOCAL_DATA_FILENAME)


def _require_username(username: str) -> str:
    username = username.strip()
    if not username:
        raise ValueError("Username tidak boleh kosong")
    return username


def _username_filename(username: str) -> str:
    return f"{quote(_require_username(username), safe='')}.json"


def get_local_data_path(username: str) -> str:
    """Return path file lokal untuk username tertentu."""
    return os.path.join(LOCAL_USERS_DIR, _username_filename(username))


def _read_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def _load(username: str) -> dict:
    username = _require_username(username)
    user_path = get_local_data_path(username)
    data = _read_json(user_path)
    if data:
        return data

    # Fallback untuk data lama dari implementasi single-user.
    legacy_data = _read_json(LOCAL_DATA_PATH)
    if legacy_data.get("username") == username:
        return legacy_data
    return {}


def _save(username: str, data: dict) -> None:
    username = _require_username(username)
    data["username"] = username
    os.makedirs(LOCAL_USERS_DIR, exist_ok=True)
    with open(get_local_data_path(username), "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def local_data_exists(username: str) -> bool:
    """Cek apakah local share untuk username sudah tersedia."""
    data = _load(username)
    return bool(data.get("enc_local_share"))


def get_username(username: str) -> str | None:
    """Ambil username dari file lokal user, jika ada."""
    return _load(username).get("username")


def save_local_share(
    username: str,
    enc_local_share: bytes,
    local_share_nonce: bytes,
    kdf_salt: bytes,
    kdf_params: dict,
) -> None:
    """Simpan local share terenkripsi dan parameter KDF milik username."""
    data = _load(username)
    data["enc_local_share"] = base64.b64encode(enc_local_share).decode()
    data["local_share_nonce"] = base64.b64encode(local_share_nonce).decode()
    data["kdf_salt"] = base64.b64encode(kdf_salt).decode()
    data["kdf_params"] = kdf_params
    _save(username, data)


def load_local_share(username: str) -> tuple[bytes, bytes, bytes, dict] | None:
    """Baca local share terenkripsi dan parameter KDF milik username."""
    data = _load(username)
    required = ["enc_local_share", "local_share_nonce", "kdf_salt", "kdf_params"]
    if not all(key in data for key in required):
        return None

    enc_local_share = base64.b64decode(data["enc_local_share"])
    local_share_nonce = base64.b64decode(data["local_share_nonce"])
    kdf_salt = base64.b64decode(data["kdf_salt"])
    kdf_params = data["kdf_params"]

    return enc_local_share, local_share_nonce, kdf_salt, kdf_params


def save_backup_vault(
    username: str,
    enc_backup_vault: bytes,
    backup_vault_nonce: bytes,
) -> None:
    """Simpan backup vault terenkripsi milik username."""
    data = _load(username)
    data["enc_backup_vault"] = base64.b64encode(enc_backup_vault).decode()
    data["backup_vault_nonce"] = base64.b64encode(backup_vault_nonce).decode()
    _save(username, data)


def load_backup_vault(username: str) -> tuple[bytes, bytes] | None:
    """Baca backup vault terenkripsi milik username."""
    data = _load(username)
    if "enc_backup_vault" not in data or "backup_vault_nonce" not in data:
        return None

    enc_backup_vault = base64.b64decode(data["enc_backup_vault"])
    backup_vault_nonce = base64.b64decode(data["backup_vault_nonce"])

    return enc_backup_vault, backup_vault_nonce


def backup_exists(username: str) -> bool:
    """Cek apakah backup vault lokal milik username sudah tersedia."""
    data = _load(username)
    return bool(data.get("enc_backup_vault"))


def clear_local_data(username: str | None = None) -> None:
    """Hapus data lokal satu username, atau semua data lokal jika username None."""
    if username is not None:
        path = get_local_data_path(username)
        if os.path.exists(path):
            os.remove(path)
            print("[LOCAL] Data lokal berhasil dihapus.")
        return

    if os.path.exists(LOCAL_DATA_PATH):
        os.remove(LOCAL_DATA_PATH)
    if os.path.isdir(LOCAL_USERS_DIR):
        for name in os.listdir(LOCAL_USERS_DIR):
            path = os.path.join(LOCAL_USERS_DIR, name)
            if os.path.isfile(path):
                os.remove(path)
        try:
            os.rmdir(LOCAL_USERS_DIR)
        except OSError:
            pass
    print("[LOCAL] Semua data lokal berhasil dihapus.")
