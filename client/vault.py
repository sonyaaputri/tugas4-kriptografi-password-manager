# ============================================================
# Manajemen vault: pembuatan, akses normal, akses backup,
# dan operasi CRUD data password
#
# Vault adalah list of dict yang disimpan sebagai JSON,
# dienkripsi dengan AES-128-GCM menggunakan master key.
#
# Struktur vault (plaintext sebelum dienkripsi):
# [
#   {
#     "nama_layanan": str,   # wajib
#     "username"    : str,   # wajib
#     "password"    : str,   # wajib
#     "catatan"     : str    # opsional, default ""
#   },
#   ...
# ]
#
# Alur pembuatan vault:
#   1. Generate master key acak (16 bytes / 128-bit)
#   2. Enkripsi vault kosong dengan AES-128-GCM
#   3. Bagi master key menjadi 3 share SSS (2,3)
#   4. Enkripsi local share dengan kunci KDF dari master password
#   5. Simpan local share terenkripsi + KDF params ke lokal
#   6. Kirim server share + vault ke server
#   7. Tampilkan recovery share ke pengguna (sekali saja)
#
# Alur akses normal:
#   1. Dekripsi local share dengan kunci KDF dari master password
#   2. Ambil server share + vault dari server
#   3. Rekonstruksi master key dari local share + server share
#   4. Dekripsi vault dengan master key
#
# Alur akses backup:
#   1. Dekripsi local share dengan kunci KDF dari master password
#   2. Terima recovery share dari pengguna
#   3. Rekonstruksi master key dari local share + recovery share
#   4. Dekripsi backup vault lokal dengan master key
# ============================================================

import json
import os
import secrets

from crypto.kdf     import derive_key
from crypto.aes_gcm import (
    encrypt_vault,
    decrypt_vault,
    encrypt_local_share,
    decrypt_local_share,
)
from crypto.sss import generate_shares, reconstruct_secret
import local_storage as storage
import api_client    as api


# ── Konstanta ────────────────────────────────────────────────

MASTER_KEY_SIZE = 16   # 128-bit untuk AES-128-GCM
SSS_THRESHOLD   = 2    # minimal 2 share untuk rekonstruksi
SSS_TOTAL       = 3    # total 3 share: local, server, recovery

# Index share (koordinat x pada polinomial SSS)
LOCAL_SHARE_INDEX    = 1
SERVER_SHARE_INDEX   = 2
RECOVERY_SHARE_INDEX = 3


# ── Pembuatan Vault ───────────────────────────────────────────

def create_vault(username: str, master_password: str) -> dict | None:
    """
    Membuat vault baru untuk pengguna.

    Alur lengkap:
    1. Generate master key acak 128-bit
    2. Buat vault kosong dan enkripsi dengan AES-128-GCM
    3. Bagi master key menjadi 3 share SSS (2,3)
    4. Turunkan kunci dari master password dengan Argon2id
    5. Enkripsi local share dengan kunci KDF
    6. Simpan local share terenkripsi + KDF params ke lokal
    7. Kirim server share + vault terenkripsi ke server
    8. Kembalikan recovery share untuk ditampilkan ke pengguna

    Parameters
    ----------
    username        : nama pengguna unik
    master_password : password utama pengguna

    Returns
    -------
    dict berisi recovery_share jika berhasil:
    {
        "index": 3,
        "value": "hex string"
    }
    None jika gagal (misalnya username sudah terdaftar).

    Catatan:
    - Master key TIDAK disimpan di manapun setelah proses ini selesai
    - Recovery share ditampilkan HANYA SATU KALI di sini
    - Server tidak pernah menerima master key, local share, recovery share
    """

    # 1. Generate master key acak 128-bit menggunakan CSPRNG (os.urandom)
    master_key = secrets.token_bytes(MASTER_KEY_SIZE)

    # 2. Buat vault kosong (list kosong) dan enkripsi
    empty_vault  = json.dumps([]).encode("utf-8")
    vault_blob, vault_nonce = encrypt_vault(empty_vault, master_key)
    vault_nonce_hex = vault_nonce.hex()

    # 3. Bagi master key menjadi 3 share SSS (2,3)
    # shares adalah list of dict: [{"index": x, "value": "hex"}, ...]
    shares = generate_shares(master_key, SSS_THRESHOLD, SSS_TOTAL)

    local_share    = shares[LOCAL_SHARE_INDEX - 1]     # index 1
    server_share   = shares[SERVER_SHARE_INDEX - 1]    # index 2
    recovery_share = shares[RECOVERY_SHARE_INDEX - 1]  # index 3

    # 4. Turunkan kunci enkripsi dari master password menggunakan Argon2id
    kdf_key, kdf_salt, kdf_params = derive_key(master_password)

    # 5. Enkripsi local share dengan kunci KDF
    # local share dikonversi ke bytes dulu sebelum dienkripsi
    local_share_bytes = json.dumps(local_share).encode("utf-8")
    enc_local_share, local_share_nonce = encrypt_local_share(
        local_share_bytes, kdf_key
    )

    # 6. Simpan local share terenkripsi + KDF params ke file lokal
    storage.save_local_share(
        username          = username,
        enc_local_share   = enc_local_share,
        local_share_nonce = local_share_nonce,
        kdf_salt          = kdf_salt,
        kdf_params        = kdf_params,
    )

    # 7. Simpan backup vault lokal (sinkron dengan vault di server)
    storage.save_backup_vault(vault_blob, vault_nonce)

    # 8. Kirim server share + vault terenkripsi ke server
    success, message = api.register_user(
        username     = username,
        server_share = server_share,
        vault_blob   = vault_blob,
        vault_nonce  = vault_nonce_hex,
    )

    if not success:
        print(f"[VAULT] Gagal register ke server: {message}")
        return None

    # Master key dihapus dari memori setelah selesai
    del master_key
    del kdf_key

    # Recovery share dikembalikan untuk ditampilkan ke pengguna (sekali saja)
    return recovery_share


# ── Akses Normal ──────────────────────────────────────────────

def open_vault_normal(master_password: str) -> list[dict] | None:
    """
    Membuka vault pada mode normal (server aktif).

    Alur:
    1. Baca local share terenkripsi dari file lokal
    2. Turunkan kunci dari master password (Argon2id + salt tersimpan)
    3. Dekripsi local share
    4. Ambil server share + vault terenkripsi dari server
    5. Rekonstruksi master key dari local share + server share
    6. Dekripsi vault dengan master key

    Parameters
    ----------
    master_password : password utama pengguna

    Returns
    -------
    List of dict berisi data password jika berhasil.
    None jika gagal (password salah, server tidak bisa diakses, dll).
    """

    # 1. Baca data lokal
    local_data = storage.load_local_share()
    if not local_data:
        print("[VAULT] Data lokal tidak ditemukan. Buat vault terlebih dahulu.")
        return None

    enc_local_share, local_share_nonce, kdf_salt, kdf_params = local_data

    # 2. Turunkan kunci dari master password menggunakan salt yang tersimpan
    kdf_key, _, _ = derive_key(master_password, kdf_salt, kdf_params)

    # 3. Dekripsi local share
    try:
        local_share_bytes = decrypt_local_share(
            enc_local_share, local_share_nonce, kdf_key
        )
        local_share = json.loads(local_share_bytes.decode("utf-8"))
    except Exception:
        print("[VAULT] Master password salah atau local share rusak.")
        return None
    finally:
        del kdf_key

    # 4. Ambil server share + vault dari server
    success, server_data = api.fetch_server_data(
        storage.get_username()
    )
    if not success:
        print("[VAULT] Gagal mengambil data dari server.")
        return None

    server_share = server_data["server_share"]
    vault_blob   = server_data["vault_blob"]
    vault_nonce  = bytes.fromhex(server_data["vault_nonce"])

    # 5. Rekonstruksi master key dari local share + server share
    try:
        master_key = reconstruct_secret([local_share, server_share])
    except Exception:
        print("[VAULT] Gagal merekonstruksi master key.")
        return None

    # 6. Dekripsi vault dengan master key
    try:
        vault_plaintext = decrypt_vault(vault_blob, vault_nonce, master_key)
        vault = json.loads(vault_plaintext.decode("utf-8"))
    except Exception:
        print("[VAULT] Dekripsi vault gagal. Data tidak ditampilkan.")
        return None
    finally:
        del master_key

    return vault


# ── Akses Backup ──────────────────────────────────────────────

def open_vault_backup(
    master_password: str,
    recovery_share: dict
) -> list[dict] | None:
    """
    Membuka vault pada mode backup (server tidak aktif).
    READ-ONLY: tidak bisa menambah, mengubah, atau menghapus data.

    Alur:
    1. Baca local share terenkripsi dari file lokal
    2. Turunkan kunci dari master password (Argon2id + salt tersimpan)
    3. Dekripsi local share
    4. Terima recovery share dari pengguna
    5. Rekonstruksi master key dari local share + recovery share
    6. Dekripsi backup vault lokal

    Parameters
    ----------
    master_password : password utama pengguna
    recovery_share  : share ke-3 yang disimpan pengguna, format dict:
                      {"index": 3, "value": "hex string"}

    Returns
    -------
    List of dict berisi data password jika berhasil.
    None jika gagal (password salah, recovery share salah, dll).
    """

    # 1. Baca data lokal
    local_data = storage.load_local_share()
    if not local_data:
        print("[VAULT] Data lokal tidak ditemukan.")
        return None

    enc_local_share, local_share_nonce, kdf_salt, kdf_params = local_data

    # 2. Turunkan kunci dari master password
    kdf_key, _, _ = derive_key(master_password, kdf_salt, kdf_params)

    # 3. Dekripsi local share
    try:
        local_share_bytes = decrypt_local_share(
            enc_local_share, local_share_nonce, kdf_key
        )
        local_share = json.loads(local_share_bytes.decode("utf-8"))
    except Exception:
        print("[VAULT] Master password salah atau local share rusak.")
        return None
    finally:
        del kdf_key

    # 4. Baca backup vault lokal
    backup_data = storage.load_backup_vault()
    if not backup_data:
        print("[VAULT] Backup vault lokal tidak ditemukan.")
        return None

    enc_backup_vault, backup_vault_nonce = backup_data

    # 5. Rekonstruksi master key dari local share + recovery share
    try:
        master_key = reconstruct_secret([local_share, recovery_share])
    except Exception:
        print("[VAULT] Gagal merekonstruksi master key dari recovery share.")
        return None

    # 6. Dekripsi backup vault lokal
    try:
        vault_plaintext = decrypt_vault(
            enc_backup_vault, backup_vault_nonce, master_key
        )
        vault = json.loads(vault_plaintext.decode("utf-8"))
    except Exception:
        print("[VAULT] Recovery share salah atau backup vault rusak.")
        return None
    finally:
        del master_key

    return vault


# ── CRUD Data Password (Mode Normal) ─────────────────────────

def _save_vault(
    vault: list[dict],
    master_password: str
) -> bool:
    """
    Enkripsi ulang vault dan simpan ke server + backup lokal.
    Dipanggil setelah setiap operasi add/edit/delete.

    Alur:
    1. Dekripsi local share untuk dapatkan master key
    2. Enkripsi ulang vault dengan nonce baru
    3. Push vault baru ke server
    4. Update backup vault lokal

    Parameters
    ----------
    vault           : list of dict isi vault (plaintext)
    master_password : password utama pengguna

    Returns
    -------
    True jika berhasil, False jika gagal.

    Catatan:
    - Nonce selalu baru setiap enkripsi ulang (AES-GCM requirement)
    - Server hanya menerima ciphertext, tidak pernah plaintext
    """

    # Ambil local share untuk rekonstruksi master key
    local_data = storage.load_local_share()
    if not local_data:
        return False

    enc_local_share, local_share_nonce, kdf_salt, kdf_params = local_data
    kdf_key, _, _ = derive_key(master_password, kdf_salt, kdf_params)

    try:
        local_share_bytes = decrypt_local_share(
            enc_local_share, local_share_nonce, kdf_key
        )
        local_share = json.loads(local_share_bytes.decode("utf-8"))
    except Exception:
        return False
    finally:
        del kdf_key

    # Ambil server share
    success, server_data = api.fetch_server_data(storage.get_username())
    if not success:
        return False

    server_share = server_data["server_share"]

    # Rekonstruksi master key
    try:
        master_key = reconstruct_secret([local_share, server_share])
    except Exception:
        return False

    # Enkripsi ulang vault dengan nonce baru
    vault_bytes = json.dumps(vault, ensure_ascii=False).encode("utf-8")
    vault_blob, vault_nonce = encrypt_vault(vault_bytes, master_key)
    vault_nonce_hex = vault_nonce.hex()

    del master_key

    # Push vault baru ke server
    ok, msg = api.push_vault(
        storage.get_username(), vault_blob, vault_nonce_hex
    )
    if not ok:
        print(f"[VAULT] Gagal push ke server: {msg}")
        return False

    # Update backup vault lokal
    storage.save_backup_vault(vault_blob, vault_nonce)

    return True


def add_entry(
    vault: list[dict],
    master_password: str,
    nama_layanan: str,
    username: str,
    password: str,
    catatan: str = ""
) -> list[dict] | None:
    """
    Menambahkan data password baru ke vault.
    Hanya bisa dilakukan pada mode normal.

    Parameters
    ----------
    vault           : list vault saat ini (hasil open_vault_normal)
    master_password : password utama pengguna
    nama_layanan    : nama layanan/website (wajib)
    username        : username/email untuk layanan (wajib)
    password        : password untuk layanan (wajib)
    catatan         : catatan opsional (default "")

    Returns
    -------
    List vault terbaru jika berhasil, None jika gagal.
    """
    entry = {
        "nama_layanan": nama_layanan,
        "username"    : username,
        "password"    : password,
        "catatan"     : catatan,
    }
    vault.append(entry)

    if not _save_vault(vault, master_password):
        vault.pop()  # rollback jika gagal
        return None

    return vault


def edit_entry(
    vault: list[dict],
    master_password: str,
    index: int,
    nama_layanan: str = None,
    username: str = None,
    password: str = None,
    catatan: str = None
) -> list[dict] | None:
    """
    Mengubah data password yang sudah tersimpan di vault.
    Hanya bisa dilakukan pada mode normal.

    Parameters
    ----------
    vault           : list vault saat ini
    master_password : password utama pengguna
    index           : index entry yang akan diubah (0-based)
    nama_layanan    : nilai baru (None = tidak diubah)
    username        : nilai baru (None = tidak diubah)
    password        : nilai baru (None = tidak diubah)
    catatan         : nilai baru (None = tidak diubah)

    Returns
    -------
    List vault terbaru jika berhasil, None jika gagal.
    """
    if index < 0 or index >= len(vault):
        print(f"[VAULT] Index {index} tidak valid.")
        return None

    # Simpan entry lama untuk rollback jika gagal
    old_entry = vault[index].copy()

    if nama_layanan is not None:
        vault[index]["nama_layanan"] = nama_layanan
    if username is not None:
        vault[index]["username"] = username
    if password is not None:
        vault[index]["password"] = password
    if catatan is not None:
        vault[index]["catatan"] = catatan

    if not _save_vault(vault, master_password):
        vault[index] = old_entry  # rollback
        return None

    return vault


def delete_entry(
    vault: list[dict],
    master_password: str,
    index: int
) -> list[dict] | None:
    """
    Menghapus data password dari vault.
    Hanya bisa dilakukan pada mode normal.

    Parameters
    ----------
    vault           : list vault saat ini
    master_password : password utama pengguna
    index           : index entry yang akan dihapus (0-based)

    Returns
    -------
    List vault terbaru jika berhasil, None jika gagal.
    """
    if index < 0 or index >= len(vault):
        print(f"[VAULT] Index {index} tidak valid.")
        return None

    # Simpan entry yang dihapus untuk rollback jika gagal
    removed_entry = vault.pop(index)

    if not _save_vault(vault, master_password):
        vault.insert(index, removed_entry)  # rollback
        return None

    return vault