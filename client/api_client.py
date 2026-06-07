# HTTP client untuk komunikasi klien ke server
#
# Bertanggung jawab untuk:
#   - Mengirim server_share + vault awal saat register
#   - Mengambil server_share + vault + nonce saat mode normal
#   - Mengirim vault baru setelah ada perubahan data
#   - Deteksi server aktif/mati (untuk trigger mode backup)
#
# Catatan zero-knowledge:
#   - Tidak pernah mengirim master key, local share, recovery share
#   - Tidak pernah mengirim plaintext vault atau password plaintext

import base64
import requests
from requests.exceptions import ConnectionError, Timeout

# URL base server, sesuaikan jika server berjalan di host/port lain
SERVER_URL = "http://127.0.0.1:5000"

# Timeout dalam detik untuk setiap request ke server
REQUEST_TIMEOUT = 5


# Helper Internal

def _is_server_response_ok(response: requests.Response) -> bool:
    """Cek apakah response server menandakan sukses."""
    try:
        return response.json().get("success", False)
    except Exception:
        return False


# Health Check

def is_server_online() -> bool:
    """
    Cek apakah server sedang aktif dengan hit endpoint /ping.

    Returns
    -------
    True  → server aktif, gunakan mode normal
    False → server tidak bisa diakses, beralih ke mode backup
    """
    try:
        resp = requests.get(
            f"{SERVER_URL}/ping",
            timeout=REQUEST_TIMEOUT
        )
        return resp.status_code == 200
    except (ConnectionError, Timeout):
        return False


# Register 

def register_user(
    username: str,
    server_share: dict,
    vault_blob: bytes,
    vault_nonce: str
) -> tuple[bool, str]:
    """
    Mendaftarkan pengguna baru ke server.
    Mengirim server_share, vault awal terenkripsi, dan nonce.

    Parameters
    ----------
    username     : nama pengguna unik
    server_share : share ke-2 hasil SSS, format dict
                   contoh: {"index": 2, "value": "a1b2c3..."}
    vault_blob   : vault kosong terenkripsi AES-128-GCM (bytes)
    vault_nonce  : nonce enkripsi vault (hex string)

    Returns
    -------
    (True, pesan)  jika berhasil
    (False, pesan) jika gagal

    Catatan zero-knowledge
    ----------------------
    Fungsi ini TIDAK mengirim:
    - master key
    - local share
    - recovery share
    - plaintext vault
    - password pengguna
    - kunci turunan KDF
    """
    import json

    # vault_blob (bytes) di-encode ke base64 agar bisa dikirim via JSON
    vault_b64 = base64.b64encode(vault_blob).decode()

    payload = {
        "username"    : username,
        "server_share": json.dumps(server_share),  # dict → JSON string
        "vault_blob"  : vault_b64,
        "vault_nonce" : vault_nonce,
    }

    try:
        resp = requests.post(
            f"{SERVER_URL}/register",
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        data = resp.json()
        return data.get("success", False), data.get("message", "")
    except (ConnectionError, Timeout):
        return False, "Server tidak dapat diakses"
    except Exception as e:
        return False, f"Error tidak terduga: {e}"


# Ambil Data Server (Mode Normal)

def fetch_server_data(username: str) -> tuple[bool, dict]:
    """
    Mengambil server_share, vault_blob, dan vault_nonce dari server.
    Dipanggil saat mode akses normal.

    Parameters
    ----------
    username : nama pengguna

    Returns
    -------
    (True, data)  jika berhasil, data berisi:
                  {
                    "server_share": dict,   # share ke-2 SSS
                    "vault_blob"  : bytes,  # vault terenkripsi
                    "vault_nonce" : str     # nonce vault (hex)
                  }
    (False, {})   jika gagal atau server tidak bisa diakses

    Setelah fungsi ini dipanggil, klien menggabungkan server_share
    dengan local_share untuk rekonstruksi master key, lalu dekripsi
    vault_blob sendiri. Server tidak terlibat dalam dekripsi.
    """
    import json

    try:
        resp = requests.get(
            f"{SERVER_URL}/vault/{username}",
            timeout=REQUEST_TIMEOUT
        )
        data = resp.json()

        if not data.get("success", False):
            return False, {}

        # vault_blob di-decode dari base64 kembali ke bytes
        vault_blob = base64.b64decode(data["vault_blob"]) \
            if data.get("vault_blob") else None

        # server_share di-parse dari JSON string ke dict
        server_share = json.loads(data["server_share"]) \
            if isinstance(data["server_share"], str) else data["server_share"]

        return True, {
            "server_share": server_share,
            "vault_blob"  : vault_blob,
            "vault_nonce" : data["vault_nonce"],
        }

    except (ConnectionError, Timeout):
        return False, {}
    except Exception as e:
        print(f"[API] Error fetch_server_data: {e}")
        return False, {}


# Update Vault (Mode Normal)

def push_vault(
    username: str,
    vault_blob: bytes,
    vault_nonce: str
) -> tuple[bool, str]:
    """
    Mengirim vault yang sudah dienkripsi ulang ke server.
    Dipanggil setelah klien menambah/mengubah/menghapus password
    di mode normal.

    Parameters
    ----------
    username    : nama pengguna
    vault_blob  : vault baru yang sudah dienkripsi ulang (bytes)
    vault_nonce : nonce baru (hex string, selalu berbeda dari sebelumnya)

    Returns
    -------
    (True, pesan)  jika berhasil
    (False, pesan) jika gagal

    Catatan:
    - vault_blob yang dikirim adalah ciphertext, bukan plaintext
    - nonce harus selalu baru setiap enkripsi ulang (AES-GCM requirement)
    - server tidak tahu isi vault yang berubah
    """
    vault_b64 = base64.b64encode(vault_blob).decode()

    payload = {
        "vault_blob" : vault_b64,
        "vault_nonce": vault_nonce,
    }

    try:
        resp = requests.put(
            f"{SERVER_URL}/vault/{username}",
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        data = resp.json()
        return data.get("success", False), data.get("message", "")
    except (ConnectionError, Timeout):
        return False, "Server tidak dapat diakses"
    except Exception as e:
        return False, f"Error tidak terduga: {e}"