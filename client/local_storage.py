# ============================================================
# Manajemen penyimpanan data lokal di sisi klien
#
# Bertanggung jawab menyimpan dan membaca:
#   - Local share terenkripsi + nonce enkripsi local share
#   - Salt KDF + parameter KDF
#   - Backup vault lokal terenkripsi + nonce backup vault
#   - Username (metadata)
#
# Semua data sensitif disimpan dalam bentuk terenkripsi.
# Local share TIDAK pernah disimpan dalam bentuk asli (plaintext).
#
# Struktur file lokal (JSON):
# {
#   "username"           : str,   # nama pengguna
#   "enc_local_share"    : str,   # local share terenkripsi (base64)
#   "local_share_nonce"  : str,   # nonce enkripsi local share (hex)
#   "kdf_salt"           : str,   # salt Argon2id (base64)
#   "kdf_params"         : dict,  # parameter Argon2id
#   "enc_backup_vault"   : str,   # backup vault terenkripsi (base64)
#   "backup_vault_nonce" : str    # nonce backup vault (hex)
# }
# ============================================================

import json
import os
import base64

# Nama file penyimpanan lokal, disimpan di direktori client/
LOCAL_DATA_FILENAME = "local_data.json"

# Direktori tempat file lokal disimpan (sama dengan lokasi file ini)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_DATA_PATH = os.path.join(BASE_DIR, LOCAL_DATA_FILENAME)


# ── Helper Internal ──────────────────────────────────────────

def _load() -> dict:
    """
    Membaca file local_data.json.
    Mengembalikan dict kosong jika file belum ada.
    """
    if not os.path.exists(LOCAL_DATA_PATH):
        return {}
    with open(LOCAL_DATA_PATH, "r") as f:
        return json.load(f)


def _save(data: dict) -> None:
    """Menyimpan data ke file local_data.json."""
    with open(LOCAL_DATA_PATH, "w") as f:
        json.dump(data, f, indent=2)


# ── Cek Vault Lokal ──────────────────────────────────────────

def local_data_exists() -> bool:
    """
    Cek apakah data lokal (local share + KDF params) sudah ada.
    Digunakan untuk menentukan apakah pengguna perlu register
    atau bisa langsung login.
    """
    data = _load()
    return bool(data.get("enc_local_share"))


def get_username() -> str | None:
    """Mengambil username yang tersimpan di lokal."""
    return _load().get("username")


# ── Local Share ───────────────────────────────────────────────

def save_local_share(
    username: str,
    enc_local_share: bytes,
    local_share_nonce: bytes,
    kdf_salt: bytes,
    kdf_params: dict
) -> None:
    """
    Menyimpan local share terenkripsi dan parameter KDF ke file lokal.

    Local share TIDAK disimpan dalam bentuk asli.
    Local share dienkripsi menggunakan kunci turunan dari master password
    sebelum dipanggil fungsi ini.

    Parameters
    ----------
    username          : nama pengguna
    enc_local_share   : local share yang sudah dienkripsi (bytes)
    local_share_nonce : nonce yang digunakan untuk enkripsi local share (bytes)
    kdf_salt          : salt Argon2id (bytes)
    kdf_params        : parameter Argon2id, contoh:
                        {
                          "time_cost"  : 3,
                          "memory_cost": 65536,
                          "parallelism": 4,
                          "hash_len"   : 32
                        }
    """
    data = _load()
    data["username"]          = username
    data["enc_local_share"]   = base64.b64encode(enc_local_share).decode()
    data["local_share_nonce"] = base64.b64encode(local_share_nonce).decode()
    data["kdf_salt"]          = base64.b64encode(kdf_salt).decode()
    data["kdf_params"]        = kdf_params
    _save(data)


def load_local_share() -> tuple[bytes, bytes, bytes, dict] | None:
    """
    Membaca local share terenkripsi dan parameter KDF dari file lokal.

    Returns
    -------
    (enc_local_share, local_share_nonce, kdf_salt, kdf_params)
    sebagai bytes, bytes, bytes, dict.
    None jika data belum ada.

    Catatan: data yang dikembalikan masih terenkripsi.
    Dekripsi dilakukan di vault.py menggunakan kunci dari master password.
    """
    data = _load()

    required = ["enc_local_share", "local_share_nonce", "kdf_salt", "kdf_params"]
    if not all(k in data for k in required):
        return None

    enc_local_share   = base64.b64decode(data["enc_local_share"])
    local_share_nonce = base64.b64decode(data["local_share_nonce"])
    kdf_salt          = base64.b64decode(data["kdf_salt"])
    kdf_params        = data["kdf_params"]

    return enc_local_share, local_share_nonce, kdf_salt, kdf_params


# ── Backup Vault ──────────────────────────────────────────────

def save_backup_vault(
    enc_backup_vault: bytes,
    backup_vault_nonce: bytes
) -> None:
    """
    Menyimpan backup vault terenkripsi ke file lokal.

    Dipanggil setiap kali vault diperbarui pada mode normal,
    agar backup lokal selalu sinkron dengan vault di server.

    Parameters
    ----------
    enc_backup_vault   : backup vault yang sudah dienkripsi AES-128-GCM (bytes)
    backup_vault_nonce : nonce yang digunakan untuk enkripsi backup (bytes)

    Catatan:
    - Backup vault adalah ciphertext, bukan plaintext
    - Nonce harus selalu baru setiap enkripsi ulang
    """
    data = _load()
    data["enc_backup_vault"]   = base64.b64encode(enc_backup_vault).decode()
    data["backup_vault_nonce"] = base64.b64encode(backup_vault_nonce).decode()
    _save(data)


def load_backup_vault() -> tuple[bytes, bytes] | None:
    """
    Membaca backup vault terenkripsi dari file lokal.
    Digunakan pada mode backup ketika server tidak dapat diakses.

    Returns
    -------
    (enc_backup_vault, backup_vault_nonce) sebagai bytes, bytes.
    None jika backup belum ada.

    Catatan: data yang dikembalikan masih terenkripsi.
    Dekripsi dilakukan di vault.py menggunakan master key hasil
    rekonstruksi dari local share + recovery share.
    """
    data = _load()

    if "enc_backup_vault" not in data or "backup_vault_nonce" not in data:
        return None

    enc_backup_vault   = base64.b64decode(data["enc_backup_vault"])
    backup_vault_nonce = base64.b64decode(data["backup_vault_nonce"])

    return enc_backup_vault, backup_vault_nonce


def backup_exists() -> bool:
    """Cek apakah backup vault lokal sudah tersedia."""
    data = _load()
    return bool(data.get("enc_backup_vault"))


# ── Reset ─────────────────────────────────────────────────────

def clear_local_data() -> None:
    """
    Menghapus semua data lokal.
    Digunakan jika pengguna ingin reset/registrasi ulang.
    """
    if os.path.exists(LOCAL_DATA_PATH):
        os.remove(LOCAL_DATA_PATH)
        print("[LOCAL] Data lokal berhasil dihapus.")