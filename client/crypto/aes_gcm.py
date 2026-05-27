# Implementasi enkripsi/dekripsi menggunakan AES-GCM
# Digunakan untuk dua keperluan berbeda:
#
# 1. Enkripsi VAULT (AES-128-GCM)
#    - Key size : 16 bytes (128-bit)
#    - Key      : master key hasil rekonstruksi SSS
#    - Nonce    : 12 bytes acak baru setiap enkripsi ulang
#    - Plaintext: JSON bytes isi vault
#    - Output   : (ciphertext+tag bytes, nonce bytes)
#
# 2. Enkripsi LOCAL SHARE (AES-256-GCM)
#    - Key size : 32 bytes (256-bit)
#    - Key      : kunci turunan Argon2id dari master password
#    - Nonce    : 12 bytes acak baru setiap enkripsi
#    - Plaintext: JSON bytes local share
#    - Output   : (ciphertext+tag bytes, nonce bytes)
#
# AES-GCM menyediakan: Confidentiality & Authentication
# Jika ciphertext atau nonce dimodifikasi, dekripsi PASTI GAGAL.

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ukuran nonce untuk AES-GCM (12 bytes = 96-bit)
_NONCE_SIZE = 12


# Enkripsi Vault (AES-128-GCM)

def encrypt_vault(plaintext: bytes, master_key: bytes) -> tuple[bytes, bytes]:
    """
    Mengenkripsi isi vault menggunakan AES-128-GCM.

    Master key 16 bytes (128-bit) dari hasil rekonstruksi SSS.
    Nonce baru dibangkitkan secara acak setiap enkripsi
    karena AES-GCM TIDAK aman jika nonce diulang dengan key yang sama.

    Parameters
    ----------
    plaintext  : bytes isi vault (JSON UTF-8 encoded)
    master_key : 16 bytes master key (AES-128)

    Returns
    -------
    (ciphertext_with_tag, nonce)
    - ciphertext_with_tag : bytes, ciphertext + 16 bytes GCM auth tag
    - nonce               : bytes 12 bytes (disimpan bersama ciphertext)

    Raises
    ------
    ValueError : jika master_key bukan 16 bytes

    Catatan
    -------
    Output ciphertext dari cryptography.AESGCM sudah include
    authentication tag 16 bytes di akhir (ciphertext || tag).
    """
    if len(master_key) != 16:
        raise ValueError(
            f"master_key harus 16 bytes (AES-128), dapat {len(master_key)} bytes"
        )

    # Generate nonce baru secara random setiap enkripsi
    nonce = os.urandom(_NONCE_SIZE)

    # Enkripsi dengan AES-128-GCM
    # AESGCM otomatis append 16-byte authentication tag ke ciphertext
    aesgcm = AESGCM(master_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return ciphertext_with_tag, nonce


def decrypt_vault(
    ciphertext_with_tag: bytes,
    nonce: bytes,
    master_key: bytes
) -> bytes:
    """
    Mendekripsi vault menggunakan AES-128-GCM.

    Verifikasi authentication tag dilakukan otomatis oleh AESGCM.
    Jika tag tidak valid (key salah, ciphertext dimodifikasi),
    exception InvalidTag akan dilempar.

    Parameters
    ----------
    ciphertext_with_tag : bytes, ciphertext + 16 bytes GCM auth tag
    nonce               : bytes 12 bytes, nonce yang digunakan saat enkripsi
    master_key          : 16 bytes master key (AES-128)

    Returns
    -------
    bytes : plaintext vault (JSON UTF-8 encoded)

    Raises
    ------
    cryptography.exceptions.InvalidTag :
        Jika authentication tag tidak valid.
        Terjadi ketika: master key salah, ciphertext rusak/dimodifikasi,
        nonce salah, atau vault dari key yang berbeda.
    ValueError :
        Jika master_key bukan 16 bytes.
    """
    if len(master_key) != 16:
        raise ValueError(
            f"master_key harus 16 bytes (AES-128), dapat {len(master_key)} bytes"
        )

    aesgcm = AESGCM(master_key)

    # Dekripsi + verifikasi tag sekaligus
    # Jika tag invalid → cryptography.exceptions.InvalidTag
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)

    return plaintext


# Enkripsi Local Share (AES-256-GCM)

def encrypt_local_share(
    local_share_bytes: bytes,
    kdf_key: bytes
) -> tuple[bytes, bytes]:
    """
    Mengenkripsi local share menggunakan AES-256-GCM.

    Kunci 32 bytes berasal dari Argon2id KDF dengan master password.
    AES-256-GCM dipilih untuk local share karena kunci KDF sudah
    256-bit, memberikan keamanan lebih tinggi dari AES-128.

    Parameters
    ----------
    local_share_bytes : bytes JSON-encoded local share
                        {"index": 1, "value": "hex..."}
    kdf_key           : 32 bytes kunci turunan Argon2id

    Returns
    -------
    (ciphertext_with_tag, nonce)
    - ciphertext_with_tag : bytes
    - nonce               : bytes 12 bytes

    Raises
    ------
    ValueError : jika kdf_key bukan 32 bytes
    """
    if len(kdf_key) != 32:
        raise ValueError(
            f"kdf_key harus 32 bytes (AES-256), dapat {len(kdf_key)} bytes"
        )

    nonce = os.urandom(_NONCE_SIZE)

    aesgcm = AESGCM(kdf_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, local_share_bytes, associated_data=None)

    return ciphertext_with_tag, nonce


def decrypt_local_share(
    ciphertext_with_tag: bytes,
    nonce: bytes,
    kdf_key: bytes
) -> bytes:
    """
    Mendekripsi local share menggunakan AES-256-GCM.

    Jika master password salah → kdf_key berbeda → tag tidak valid →
    InvalidTag exception → akses ditolak (tidak ada plaintext yang bocor).

    Parameters
    ----------
    ciphertext_with_tag : bytes ciphertext + tag
    nonce               : bytes 12 bytes nonce enkripsi
    kdf_key             : 32 bytes kunci turunan Argon2id

    Returns
    -------
    bytes : JSON-encoded local share

    Raises
    ------
    cryptography.exceptions.InvalidTag :
        Jika master password salah atau local share dimodifikasi.
    ValueError :
        Jika kdf_key bukan 32 bytes.
    """
    if len(kdf_key) != 32:
        raise ValueError(
            f"kdf_key harus 32 bytes (AES-256), dapat {len(kdf_key)} bytes"
        )

    aesgcm = AESGCM(kdf_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)

    return plaintext