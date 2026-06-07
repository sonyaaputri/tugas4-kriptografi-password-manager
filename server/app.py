# Flask server untuk Password Manager Terdistribusi
#
# Prinsip zero-knowledge:
#   - Server hanya menyimpan server_share, vault terenkripsi, nonce
#   - Server tidak pernah menerima/menyimpan master key, local share,
#     recovery share, plaintext vault, password plaintext, kunci KDF
#   - Server tidak melakukan enkripsi/dekripsi apapun

from flask import Flask, request, jsonify
import database as db
from config import HOST, PORT, DEBUG
import base64

app = Flask(__name__)


# Helper

def error(message: str, code: int):
    """Helper untuk mengembalikan response error."""
    return jsonify({"success": False, "message": message}), code


def ok(data: dict = None, message: str = "OK"):
    """Helper untuk mengembalikan response sukses."""
    payload = {"success": True, "message": message}
    if data:
        payload.update(data)
    return jsonify(payload), 200


# Endpoint: Register

@app.route("/register", methods=["POST"])
def register():
    """
    Mendaftarkan pengguna baru dan menyimpan data vault awal.

    Request JSON:
    {
        "username"    : str,  -- nama pengguna
        "server_share": str,  -- share ke-2 SSS (JSON string)
        "vault_blob"  : str,  -- vault terenkripsi (base64)
        "vault_nonce" : str   -- nonce vault (hex)
    }

    Catatan: endpoint ini TIDAK menerima master key, local share,
    recovery share, atau plaintext vault.
    """
    data = request.get_json(silent=True)
    if not data:
        return error("Request body tidak valid", 400)

    required = ["username", "server_share", "vault_blob", "vault_nonce"]
    for field in required:
        if field not in data:
            return error(f"Field '{field}' wajib ada", 400)

    username     = data["username"].strip()
    server_share = data["server_share"]
    vault_nonce  = data["vault_nonce"]

    # vault_blob dikirim klien sebagai base64 string → decode ke bytes untuk BLOB
    try:
        vault_blob = base64.b64decode(data["vault_blob"])
    except Exception:
        return error("vault_blob bukan base64 yang valid", 400)

    success = db.create_user(username, server_share, vault_blob, vault_nonce)
    if not success:
        return error(f"Username '{username}' sudah terdaftar", 409)

    from flask import jsonify as _jsonify
    return _jsonify({"success": True, "message": f"Pengguna '{username}' berhasil didaftarkan"}), 201


# Endpoint: Get Server Data (Mode Normal)

@app.route("/vault/<username>", methods=["GET"])
def get_vault(username: str):
    """
    Mengirimkan server_share, vault_blob, vault_nonce ke klien.
    Dipanggil klien pada mode akses normal.

    Response JSON:
    {
        "success"     : true,
        "server_share": str,  -- share ke-2 SSS
        "vault_blob"  : str,  -- vault terenkripsi (base64)
        "vault_nonce" : str   -- nonce vault (hex)
    }

    Klien menggabungkan server_share + local_share untuk rekonstruksi
    master key, lalu mendekripsi vault_blob sendiri.
    Server tidak terlibat dalam proses dekripsi.
    """
    server_data = db.get_server_data(username)
    if not server_data:
        return error(f"Pengguna '{username}' tidak ditemukan", 404)

    # vault_blob (bytes BLOB) di-encode ke base64 untuk dikirim via JSON
    vault_b64 = base64.b64encode(server_data["vault_blob"]).decode() \
        if server_data["vault_blob"] else None

    return ok({
        "server_share": server_data["server_share"],
        "vault_blob"  : vault_b64,
        "vault_nonce" : server_data["vault_nonce"],
    })


# Endpoint: Update Vault (Mode Normal)

@app.route("/vault/<username>", methods=["PUT"])
def update_vault(username: str):
    """
    Menerima vault baru yang sudah dienkripsi ulang dari klien.
    Dipanggil setelah klien menambah/mengubah/menghapus password.

    Request JSON:
    {
        "vault_blob" : str,  -- vault baru terenkripsi (base64)
        "vault_nonce": str   -- nonce baru (hex, selalu berbeda)
    }

    Server hanya menyimpan ciphertext baru + nonce baru.
    Server tidak tahu isi vault yang berubah.
    """
    if not db.user_exists(username):
        return error(f"Pengguna '{username}' tidak ditemukan", 404)

    data = request.get_json(silent=True)
    if not data:
        return error("Request body tidak valid", 400)

    if "vault_blob" not in data or "vault_nonce" not in data:
        return error("Field 'vault_blob' dan 'vault_nonce' wajib ada", 400)

    try:
        vault_blob = base64.b64decode(data["vault_blob"])
    except Exception:
        return error("vault_blob bukan base64 yang valid", 400)

    vault_nonce = data["vault_nonce"]

    success = db.update_vault(username, vault_blob, vault_nonce)
    if not success:
        return error("Gagal memperbarui vault", 500)

    return ok(message="Vault berhasil diperbarui")


# ── Endpoint: Health Check ────────────────────────────────────

@app.route("/ping", methods=["GET"])
def ping():
    """
    Health check endpoint.
    Digunakan klien untuk mendeteksi apakah server aktif.
    Jika tidak bisa diakses → klien otomatis beralih ke mode backup.
    """
    return ok(message="pong")


# Entry Point

if __name__ == "__main__":
    db.init_db()
    print(f"[SERVER] Berjalan di http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=DEBUG)