# ============================================================
# Handler SQLite untuk server Password Manager
# ============================================================

import sqlite3
import os
from config import DB_PATH


def get_connection() -> sqlite3.Connection:
    """
    Membuka koneksi ke database SQLite.
    row_factory diset agar hasil query bisa diakses seperti dict.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Inisialisasi database: membuat tabel jika belum ada.
    Dipanggil saat server pertama kali dijalankan.
    """
    schema_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "schema.sql"
    )
    with get_connection() as conn:
        with open(schema_path, "r") as f:
            conn.executescript(f.read())
    print(f"[DB] Database siap di: {DB_PATH}")


# ── USER ─────────────────────────────────────────────────────

def user_exists(username: str) -> bool:
    """Cek apakah username sudah terdaftar."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row is not None


def create_user(
    username: str,
    server_share: str,
    vault_blob: bytes,
    vault_nonce: str
) -> bool:
    """
    Mendaftarkan pengguna baru dan menyimpan data awal vault.

    Parameters
    ----------
    username     : nama pengguna unik
    server_share : share ke-2 dari SSS, format JSON string
                   contoh: '{"index": 2, "value": "a1b2c3..."}'
    vault_blob   : vault kosong terenkripsi AES-128-GCM (bytes/BLOB)
    vault_nonce  : nonce enkripsi vault, hex string 24 karakter

    Returns
    -------
    True jika berhasil, False jika username sudah ada.

    Catatan zero-knowledge
    ----------------------
    Fungsi ini TIDAK menerima dan TIDAK menyimpan:
    - master key
    - local share
    - recovery share
    - plaintext vault
    - password pengguna
    - kunci turunan KDF
    """
    if user_exists(username):
        return False
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users (username, server_share, vault_blob, vault_nonce)
            VALUES (?, ?, ?, ?)
            """,
            (username, server_share, vault_blob, vault_nonce),
        )
    return True


def get_user(username: str) -> dict | None:
    """
    Mengambil seluruh data pengguna dari database.

    Returns
    -------
    Dict berisi: id, username, server_share, vault_blob, vault_nonce,
    created_at, updated_at.
    None jika pengguna tidak ditemukan.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def update_vault(
    username: str,
    vault_blob: bytes,
    vault_nonce: str
) -> bool:
    """
    Memperbarui vault terenkripsi dan nonce setelah ada perubahan data.

    Dipanggil klien setelah menambah/mengubah/menghapus password di
    mode normal. Vault yang diterima sudah dienkripsi ulang dengan
    nonce baru di sisi klien — server tidak melakukan enkripsi apapun.

    Parameters
    ----------
    vault_blob  : vault baru yang sudah dienkripsi ulang (BLOB)
    vault_nonce : nonce baru, selalu berbeda dari nonce sebelumnya

    Returns
    -------
    True jika berhasil, False jika username tidak ditemukan.
    """
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET vault_blob  = ?,
                vault_nonce = ?,
                updated_at  = datetime('now')
            WHERE username = ?
            """,
            (vault_blob, vault_nonce, username),
        )
    return cursor.rowcount > 0


def get_server_data(username: str) -> dict | None:
    """
    Mengambil data yang dikirim ke klien pada mode akses normal:
    server_share, vault_blob, vault_nonce.

    Ini adalah satu-satunya data yang keluar dari server ke klien.
    Server tidak pernah mengirim master key atau data sensitif lain.
    """
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT server_share, vault_blob, vault_nonce
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    return dict(row) if row else None