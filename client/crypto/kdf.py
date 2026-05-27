# Key Derivation Function (KDF) menggunakan Argon2id
#
# Argon2id dipilih karena:
#   - Pemenang Password Hashing Competition 2015
#   - Resistant terhadap brute-force dengan time & memory cost
#   - Hybrid dari Argon2i (side-channel resistant) dan Argon2d
#     (GPU attack resistant)
#   - Direkomendasikan oleh OWASP dan NIST
#
# Fungsi ini menurunkan kunci 32-byte dari master password dan salt.
# Kunci ini digunakan untuk mengenkripsi/mendekripsi local share.
#
# Alur penggunaan:
#   1. Saat create_vault:
#      kdf_key, salt, params = derive_key(master_password)
#      # salt dan params disimpan di file lokal
#
#   2. Saat open_vault (login):
#      kdf_key, _, _ = derive_key(master_password, salt, params)
#      # salt dan params dibaca dari file lokal
#
# Library: argon2-cffi

import os
import secrets
from argon2.low_level import Type, hash_secret_raw

# Parameter Default Argon2id
# Parameter ini menyeimbangkan keamanan dan performa.
# Rekomendasi OWASP 2023 untuk Argon2id:
#   - time_cost   >= 1
#   - memory_cost >= 64 MB (65536 KB)
#   - parallelism >= 4

_DEFAULT_KDF_PARAMS = {
    "time_cost"   : 3,        # iterasi (lebih tinggi = lebih lambat/aman)
    "memory_cost" : 65536,    # 64 MB dalam KiB
    "parallelism" : 4,        # jumlah thread paralel
    "hash_len"    : 32,       # output 32 bytes (256-bit) untuk AES-256-GCM
    "type"        : "argon2id"  # tipe algoritma
}

# Ukuran salt: 16 bytes = 128-bit
_SALT_SIZE = 16


# Derive Key

def derive_key(
    master_password: str,
    salt: bytes = None,
    params: dict = None
) -> tuple[bytes, bytes, dict]:
    """
    Menurunkan kunci kriptografi dari master password menggunakan Argon2id.

    Jika salt tidak diberikan, salt baru dibangkitkan secara random.
    Mode ini digunakan saat pembuatan vault (create_vault).

    Jika salt diberikan, digunakan salt yang ada.
    Mode ini digunakan saat login (open_vault) dengan salt tersimpan.

    Parameters
    ----------
    master_password : password utama pengguna (plaintext string)
    salt            : bytes salt 16 bytes (None → generate baru)
    params          : dict parameter Argon2id (None → gunakan default)
                      Keys: time_cost, memory_cost, parallelism, hash_len

    Returns
    -------
    (kdf_key, salt, params_used)
    - kdf_key    : bytes 32 bytes kunci untuk AES-256-GCM
    - salt       : bytes 16 bytes salt yang digunakan (disimpan di lokal)
    - params_used: dict parameter yang digunakan (disimpan di lokal)

    Catatan keamanan
    ----------------
    - master_password TIDAK pernah disimpan (hanya kdf_key yang digunakan)
    - salt disimpan di file lokal (tidak rahasia, berfungsi sebagai
      input unik untuk Argon2id)
    - params disimpan untuk memastikan kompatibilitas saat login ulang
    - kdf_key TIDAK disimpan; hanya digunakan sementara di memori
    """
    # Gunakan parameter default jika tidak diberikan
    if params is None:
        params = _DEFAULT_KDF_PARAMS.copy()

    # Generate salt baru jika tidak diberikan (mode create_vault)
    if salt is None:
        salt = secrets.token_bytes(_SALT_SIZE)

    # Argon2id membutuhkan tipe dari enum Type
    # Selalu gunakan Argon2id (Type.ID)
    argon2_type = Type.ID

    # Derive key menggunakan Argon2id
    # argon2.low_level.hash_secret_raw memberikan output raw bytes
    kdf_key = hash_secret_raw(
        secret      = master_password.encode("utf-8"),  # password → bytes
        salt        = salt,
        time_cost   = params["time_cost"],
        memory_cost = params["memory_cost"],
        parallelism = params["parallelism"],
        hash_len    = params["hash_len"],
        type        = argon2_type,
    )

    # Buat salinan params yang akan disimpan (tanpa field 'type' internal)
    params_to_save = {
        "time_cost"   : params["time_cost"],
        "memory_cost" : params["memory_cost"],
        "parallelism" : params["parallelism"],
        "hash_len"    : params["hash_len"],
        "type"        : "argon2id",
    }

    return kdf_key, salt, params_to_save


# Informasi Parameter

def get_default_params() -> dict:
    """
    Mengembalikan parameter Argon2id default yang digunakan.
    Berguna untuk keperluan logging/debugging.

    Returns
    -------
    dict : salinan parameter default
    """
    return _DEFAULT_KDF_PARAMS.copy()